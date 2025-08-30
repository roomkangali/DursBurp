# DursBurp - AI-Powered Security Analysis for Burp Suite
#
# Author: Kang Ali
# Version: 1.0.0
# GitHub: https://github.com/roomkangali/DursBurp
#
# This module handles the creation of structured scan issue objects.

from burp import IScanIssue

class DursBurpIssue(IScanIssue):
    def __init__(self, http_service, url, http_messages, name, detail, background, remediation, severity, confidence):
        self._http_service = http_service
        self._url = url
        self._http_messages = http_messages
        self._name = name
        self._detail = detail
        self._background = background
        self._remediation = remediation
        self._severity = severity
        self._confidence = confidence

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return self._confidence

    def getIssueBackground(self):
        return self._background

    def getRemediationBackground(self):
        return None

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        return self._remediation

    def getHttpMessages(self):
        return self._http_messages

    def getHttpService(self):
        return self._http_service

class ReportGenerator:
    def __init__(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()

    def parse_ai_report(self, report_text, http_service, url, http_messages):
        # Simple parsing logic. This should be made more robust.
        name = "AI Analysis Finding"
        detail = report_text
        background = "This issue was identified by an AI assistant."
        remediation = "Manual verification is required."
        severity = "Information"
        confidence = "Tentative"

        # Extract sections if they exist
        if "## Issue Detail" in report_text:
            detail = report_text.split("## Issue Detail")[1].split("##")[0]
        if "## Issue Background" in report_text:
            background = report_text.split("## Issue Background")[1].split("##")[0]
        if "## Remediation" in report_text:
            remediation = report_text.split("## Remediation")[1].split("##")[0]
        if "**Severity:**" in report_text:
            severity = report_text.split("**Severity:**")[1].split("\n")[0].strip()
        if "**Confidence:**" in report_text:
            confidence = report_text.split("**Confidence:**")[1].split("\n")[0].strip()
        if "# " in report_text:
            name = report_text.split("# ")[1].split("\n")[0].strip()


        return DursBurpIssue(
            http_service,
            url,
            http_messages,
            name,
            detail,
            background,
            remediation,
            severity,
            confidence
        )
