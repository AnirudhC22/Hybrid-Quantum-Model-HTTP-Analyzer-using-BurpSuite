# coding: utf-8
"""
Burp Suite Extension — AI Attack Detector
==========================================
Load this file in Burp Suite via:
  Extender > Extensions > Add > Extension type: Python > Select this file

Requires Jython 2.7+ standalone jar configured in Extender > Options.

The extension adds:
  - A right-click context menu: "Scan with AI Detector"
  - A custom "AI Attack Detector" tab in Burp
  - Passive scan check on every proxied request
  - Visual highlighting of malicious requests in Proxy history
"""

from burp import IBurpExtender, ITab, IContextMenuFactory, IScannerCheck
from burp import IScanIssue, IHttpListener
from javax.swing import (JPanel, JScrollPane, JTable, JLabel, JButton,
                          JSplitPane, JTextArea, BorderFactory, SwingConstants,
                          JCheckBox, Box, BoxLayout)
from javax.swing.table import DefaultTableModel, DefaultTableCellRenderer
from java.awt import (BorderLayout, Color, Font, Dimension, FlowLayout,
                      GridBagLayout, GridBagConstraints, Insets)
from java.lang import Runnable
from javax.swing import SwingUtilities
import java.io.PrintWriter as PrintWriter
import urllib2
import json
import threading

API_URL     = "http://127.0.0.1:5000/analyze"
BATCH_URL   = "http://127.0.0.1:5000/analyze_batch"
EXT_NAME    = "AI Attack Detector"
VERSION     = "1.0"

# Highlight colors for Proxy history
COLOR_MAP = {
    "sqli":                   Color(255, 102, 102),   # red
    "xss":                    Color(255, 178, 102),   # orange
    "cmdi":                   Color(204, 102, 255),   # purple
    "traversal":              Color(255, 255, 102),   # yellow
    "suspicious (zero-day?)": Color(102, 255, 178),   # green
}


# ─────────────────────────────────────────────────────────────────────────────
#  API helper
# ─────────────────────────────────────────────────────────────────────────────

def _call_api(req_dict):
    """POST a request dict to the Flask API and return the result dict."""
    body    = json.dumps(req_dict)
    request = urllib2.Request(API_URL, body,
                              {"Content-Type": "application/json"})
    try:
        response = urllib2.urlopen(request, timeout=5)
        return json.loads(response.read())
    except Exception as e:
        return {"error": str(e), "is_malicious": False,
                "label": "error", "confidence": 0}


def _parse_request(helpers, http_request_response):
    """Extract url/params/headers/method from a Burp IHttpRequestResponse."""
    info    = helpers.analyzeRequest(http_request_response)
    url_obj = info.getUrl()
    headers = info.getHeaders()
    method  = headers[0].split(" ")[0] if headers else "GET"
    url     = str(url_obj)
    params  = str(url_obj.getQuery()) if url_obj.getQuery() else ""
    header_str = "\r\n".join(str(h) for h in headers[1:])

    body_bytes = http_request_response.getRequest()
    body_offset = info.getBodyOffset()
    body = ""
    if body_bytes and len(body_bytes) > body_offset:
        try:
            body = helpers.bytesToString(body_bytes[body_offset:])
        except Exception:
            pass

    return {
        "url":     url,
        "params":  params + ("&" + body if body else ""),
        "headers": header_str,
        "method":  method,
    }


# ─────────────────────────────────────────────────────────────────────────────
#  Main extension class
# ─────────────────────────────────────────────────────────────────────────────

class BurpExtender(IBurpExtender, ITab, IContextMenuFactory,
                   IScannerCheck, IHttpListener):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers   = callbacks.getHelpers()
        self._stdout    = PrintWriter(callbacks.getStdout(), True)
        self._results   = []   # list of dicts shown in the table

        callbacks.setExtensionName(EXT_NAME)
        callbacks.registerContextMenuFactory(self)
        callbacks.registerScannerCheck(self)
        callbacks.registerHttpListener(self)

        self._build_ui()
        callbacks.addSuiteTab(self)
        self._stdout.println("[{}] v{} loaded. API: {}".format(
            EXT_NAME, VERSION, API_URL))

    # ── ITab ──────────────────────────────────────────────────────────────

    def getTabCaption(self):
        return EXT_NAME

    def getUiComponent(self):
        return self._panel

    # ── UI construction ───────────────────────────────────────────────────

    def _build_ui(self):
        self._panel = JPanel(BorderLayout())

        # ── Top toolbar ──
        toolbar = JPanel(FlowLayout(FlowLayout.LEFT))
        title   = JLabel("{} v{}".format(EXT_NAME, VERSION))
        title.setFont(Font("SansSerif", Font.BOLD, 14))
        toolbar.add(title)

        self._auto_scan_cb = JCheckBox("Auto-scan proxy traffic", False)
        toolbar.add(self._auto_scan_cb)

        clear_btn = JButton("Clear results")
        clear_btn.addActionListener(lambda e: self._clear_results())
        toolbar.add(clear_btn)

        self._status = JLabel("  Ready — run API server first (python api_server.py)")
        self._status.setForeground(Color(80, 80, 80))
        toolbar.add(self._status)

        # ── Results table ──
        self._table_model = DefaultTableModel(
            ["#", "Method", "URL", "Attack Type", "Confidence", "Stage"],
            0
        )
        self._table = JTable(self._table_model)
        self._table.setRowHeight(22)
        self._table.getSelectionModel().addListSelectionListener(
            lambda e: self._on_row_select()
        )

        # ── Detail panel ──
        self._detail = JTextArea(10, 60)
        self._detail.setEditable(False)
        self._detail.setFont(Font("Monospaced", Font.PLAIN, 12))
        self._detail.setBorder(BorderFactory.createTitledBorder("Details"))

        split = JSplitPane(
            JSplitPane.VERTICAL_SPLIT,
            JScrollPane(self._table),
            JScrollPane(self._detail)
        )
        split.setDividerLocation(320)

        self._panel.add(toolbar, BorderLayout.NORTH)
        self._panel.add(split,   BorderLayout.CENTER)

    def _clear_results(self):
        self._results = []
        self._table_model.setRowCount(0)
        self._detail.setText("")
        self._status.setText("  Results cleared.")

    def _add_result(self, req_dict, result):
        row_num = len(self._results) + 1
        self._results.append({"request": req_dict, "result": result})
        label = result.get("label", "unknown")
        conf  = "{:.1f}%".format(result.get("confidence", 0))
        stage = result.get("stage", "-")
        url   = req_dict.get("url", "")[:80]
        method = req_dict.get("method", "GET")

        def _add():
            self._table_model.addRow([row_num, method, url, label, conf, stage])
            # Color the label cell
            if result.get("is_malicious") and label in COLOR_MAP:
                row_idx = self._table_model.getRowCount() - 1
                self._table.setRowSelectionInterval(row_idx, row_idx)
        SwingUtilities.invokeLater(_add)

    def _on_row_select(self):
        row = self._table.getSelectedRow()
        if row < 0 or row >= len(self._results):
            return
        entry  = self._results[row]
        result = entry["result"]
        req    = entry["request"]
        text   = (
            "URL      : {}\n"
            "Method   : {}\n"
            "Params   : {}\n\n"
            "VERDICT  : {}\n"
            "Confidence: {:.1f}%\n"
            "Stage    : {}\n\n"
            "Details  : {}\n"
        ).format(
            req.get("url", ""),
            req.get("method", ""),
            req.get("params", ""),
            result.get("label", "").upper(),
            result.get("confidence", 0),
            result.get("stage", ""),
            json.dumps(result.get("details", {}), indent=2),
        )
        self._detail.setText(text)

    # ── Context menu ─────────────────────────────────────────────────────

    def createMenuItems(self, invocation):
        from javax.swing import JMenuItem
        from java.util import ArrayList
        items   = ArrayList()
        scan_btn = JMenuItem("Scan with AI Detector")

        def do_scan(event):
            selected = invocation.getSelectedMessages()
            if not selected:
                return
            def _worker():
                self._status.setText("  Scanning {} request(s)…".format(len(selected)))
                for msg in selected:
                    req_dict = _parse_request(self._helpers, msg)
                    result   = _call_api(req_dict)
                    self._add_result(req_dict, result)
                    if result.get("is_malicious"):
                        color = COLOR_MAP.get(result.get("label"), Color.ORANGE)
                        msg.setHighlight(_swing_color_to_burp(color))
                        msg.setComment(result.get("label", "attack"))
                self._status.setText("  Scan complete.")
            threading.Thread(target=_worker).start()

        scan_btn.addActionListener(do_scan)
        items.add(scan_btn)
        return items

    # ── IHttpListener (passive auto-scan) ─────────────────────────────────

    def processHttpMessage(self, toolFlag, messageIsRequest, msg):
        if messageIsRequest:
            return
        if not self._auto_scan_cb.isSelected():
            return
        # Only scan Proxy traffic (toolFlag == 4)
        if toolFlag != self._callbacks.TOOL_PROXY:
            return
        def _worker():
            req_dict = _parse_request(self._helpers, msg)
            result   = _call_api(req_dict)
            if result.get("is_malicious"):
                self._add_result(req_dict, result)
                color = COLOR_MAP.get(result.get("label"), Color.ORANGE)
                msg.setHighlight(_swing_color_to_burp(color))
                msg.setComment(result.get("label", "attack"))
        threading.Thread(target=_worker).start()

    # ── IScannerCheck (active/passive scan integration) ───────────────────

    def doPassiveScan(self, baseRequestResponse):
        req_dict = _parse_request(self._helpers, baseRequestResponse)
        result   = _call_api(req_dict)
        if result.get("is_malicious"):
            self._add_result(req_dict, result)
            return [_make_issue(self._callbacks, self._helpers,
                                baseRequestResponse, result)]
        return []

    def doActiveScan(self, baseRequestResponse, insertionPoint):
        return []

    def consolidateDuplicateIssues(self, existing, newIssue):
        return 0


# ─────────────────────────────────────────────────────────────────────────────
#  Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _swing_color_to_burp(color):
    """Map a rough Color to a Burp highlight string."""
    r, g, b = color.getRed(), color.getGreen(), color.getBlue()
    if r > 200 and g < 120:  return "red"
    if r > 200 and g > 150:  return "orange"
    if r > 200 and b < 120:  return "yellow"
    if g > 200 and b > 200:  return "cyan"
    if b > 200 and r < 120:  return "blue"
    if r > 150 and b > 150:  return "magenta"
    return "gray"


class _ScanIssue(IScanIssue):
    def __init__(self, callbacks, helpers, base, result):
        self._url        = helpers.analyzeRequest(base).getUrl()
        self._http       = [base]
        self._name       = "AI Detected: {}".format(result.get("label", "Attack").upper())
        self._detail     = (
            "The AI Attack Detector flagged this request.<br>"
            "<b>Label:</b> {}<br><b>Confidence:</b> {:.1f}%<br>"
            "<b>Stage:</b> {}"
        ).format(result.get("label"), result.get("confidence", 0),
                 result.get("stage", ""))
        self._severity   = "High" if result.get("confidence", 0) > 80 else "Medium"

    def getUrl(self):             return self._url
    def getHttpMessages(self):    return self._http
    def getHttpService(self):     return self._http[0].getHttpService()
    def getIssueName(self):       return self._name
    def getIssueType(self):       return 0x08000000
    def getSeverity(self):        return self._severity
    def getConfidence(self):      return "Firm"
    def getIssueBackground(self): return None
    def getRemediationBackground(self): return None
    def getIssueDetail(self):     return self._detail
    def getRemediationDetail(self): return None


def _make_issue(callbacks, helpers, base, result):
    return _ScanIssue(callbacks, helpers, base, result)
