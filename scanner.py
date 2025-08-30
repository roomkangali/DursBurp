# DursBurp - AI-Powered Security Analysis for Burp Suite
#
# Author: Kang Ali
# Version: 1.0.0
# GitHub: https://github.com/roomkangali/DursBurp
#
# This module handles the analysis logic, including threading.

from burp import IScanIssue
from java.io import PrintWriter
from java.util import ArrayList
from prompt_handler import PromptHandler
from api_client import APIClient
from report_generator import ReportGenerator
from javax.swing import SwingUtilities
import threading

class Scanner:
    def __init__(self, callbacks, ui):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self.ui = ui
        self.prompt_handler = PromptHandler(callbacks)
        self.api_client = APIClient()
        self.report_generator = ReportGenerator(callbacks)
        self.stdout = PrintWriter(callbacks.getStdout(), True) if hasattr(callbacks, 'getStdout') else None
    
    def doPassiveScan(self, baseRequestResponse):
        request_info = self._helpers.analyzeRequest(baseRequestResponse)
        response = baseRequestResponse.getResponse()
        if response:
            response_info = self._helpers.analyzeResponse(response)
            result = self.process_request_response(baseRequestResponse.getRequest(), request_info, response, baseRequestResponse.getHttpService())
            if result:
                return [self.report_generator.create_scan_issue(
                    baseRequestResponse.getHttpService(),
                    request_info.getUrl(),
                    [baseRequestResponse],
                    result
                )]
        return []
    
    def analyze_single_request(self, invocation):
        messages = invocation.getSelectedMessages()
        if not messages:
            return

        message = messages[0]
        request_info = self._helpers.analyzeRequest(message)
        url = str(request_info.getUrl())

        # Add a placeholder to the UI and get its index
        placeholder_index = self.ui.add_placeholder_issue(url)

        # Run the analysis in a background thread
        thread = threading.Thread(target=self._run_analysis_in_background, args=(message, request_info, url, placeholder_index))
        thread.start()

    def _run_analysis_in_background(self, message, request_info, url, index):
        response = message.getResponse()
        if response:
            result_text = self.process_request_response(message.getRequest(), request_info, response, message.getHttpService())
            
            if result_text:
                issue = self.report_generator.parse_ai_report(
                    result_text,
                    message.getHttpService(),
                    request_info.getUrl(),
                    [self._callbacks.applyMarkers(message, None, None)]
                )
                # Update the UI on the Event Dispatch Thread
                SwingUtilities.invokeLater(lambda: self.ui.update_issue(index, issue))
            else:
                # Handle analysis failure
                failed_issue = self.report_generator.parse_ai_report(
                    "# Analysis Failed\n**Severity:** Information\n**Confidence:** Certain\n## Issue Detail\n The AI failed to return a valid report.",
                    message.getHttpService(),
                    request_info.getUrl(),
                    [self._callbacks.applyMarkers(message, None, None)]
                )
                SwingUtilities.invokeLater(lambda: self.ui.update_issue(index, failed_issue))
    
    def process_request_response(self, request_bytes, request_info, response, http_service):
        try:
            # Get settings from UI
            api_choice = self.ui.get_api_choice()
            api_key = self.ui.get_api_key(api_choice)
            model = self.ui.get_model()
            max_prompt_size = self.ui.get_max_prompt_size()
            prompt = self.ui.get_prompt()
            
            # Process prompt
            processed_prompt = self.prompt_handler.process_prompt(
                prompt, request_bytes, request_info, response, self._helpers, max_prompt_size
            )
            
            # Call API
            result = self.api_client.call_api(api_choice, api_key, model, processed_prompt, max_prompt_size)
            return result
        except Exception as e:
            if self.stdout:
                self.stdout.println("Error in process_request_response: " + str(e))
            else:
                print("Error in process_request_response: " + str(e))
            return None
