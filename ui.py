# DursBurp - AI-Powered Security Analysis for Burp Suite
#
# Author: Kang Ali
# Version: 1.0.0
# GitHub: https://github.com/roomkangali/DursBurp
#
# This module handles the user interface for the extension.

from javax.swing import (JPanel, JLabel, JTextField, JComboBox, JTextArea, 
                         JRadioButton, ButtonGroup, JScrollPane, JButton,
                         JSplitPane, JList, DefaultListModel, JEditorPane,
                         JPopupMenu, JMenuItem, JTabbedPane, DefaultListCellRenderer)
from java.awt import BorderLayout, FlowLayout, Color
from java.awt.event import MouseAdapter, MouseEvent
import re

class FalsePositiveRenderer(DefaultListCellRenderer):
    def getListCellRendererComponent(self, list, value, index, isSelected, cellHasFocus):
        component = DefaultListCellRenderer.getListCellRendererComponent(self, list, value, index, isSelected, cellHasFocus)
        if "False Positive" in str(value):
            component.setBackground(Color(220, 255, 220)) # Light green
            if isSelected:
                component.setBackground(Color(180, 220, 180)) # Darker green for selection
        elif isSelected:
            component.setBackground(list.getSelectionBackground())
        else:
            component.setBackground(list.getBackground())
        return component

class UI:
    def __init__(self, callbacks):
        self._callbacks = callbacks
        self.api_choice = "OpenAI"
        self.api_key_openai = ""
        self.api_key_gemini = ""
        self.api_key_groq = ""
        self.model = "OpenAI-gpt-3.5-turbo"
        self.max_prompt_size = 2048
        self.prompt = self.get_default_prompt()
        
        # For results view
        self.results_data = {}
        self.results_list_model = DefaultListModel()
        self.current_issue = None
        
        self.create_ui()
    
    def get_default_prompt(self):
        return """Analyze the following request and response for potential vulnerabilities including, but not limited to: XSS, SQLi, LFI, Open Redirect, SSRF, Exposed Panels, IDOR, CSRF, Command Injection, SSTI, Security Headers, CORS, File Upload, BOLA, Mass Assignment, GraphQL, Blind SSRF, and DOM XSS.
For each identified vulnerability, provide a "Proof of Concept" section with specific, actionable payloads that can be used for manual testing. For contextual vulnerabilities like IDOR and BOLA, analyze identifiers in the request and suggest concrete values to try.

Provide the report in a structured Markdown format with the following sections:
# [Vulnerability Name]
**Severity:** [High/Medium/Low/Information]
**Confidence:** [Certain/Firm/Tentative]

## Issue Detail
[Detailed explanation of the vulnerability, including the Proof of Concept]

## Issue Background
[General information about this type of vulnerability]

## Remediation
[Steps to fix the vulnerability]

Request to analyze:
URL: {URL}
Method: {METHOD}
Request Headers: {REQUEST_HEADERS}
Request Body: {REQUEST_BODY}
Response Headers: {RESPONSE_HEADERS}
Response Body: {RESPONSE_BODY}"""
    
    def create_ui(self):
        # --- Top Panel (Settings) ---
        settings_container = JPanel(BorderLayout())
        
        # API choice
        api_panel = JPanel(FlowLayout())
        api_panel.add(JLabel("API: "))
        self.openai_radio = JRadioButton("OpenAI", True)
        self.gemini_radio = JRadioButton("Gemini")
        self.groq_radio = JRadioButton("Groq")
        group = ButtonGroup()
        group.add(self.openai_radio)
        group.add(self.gemini_radio)
        group.add(self.groq_radio)
        api_panel.add(self.openai_radio)
        api_panel.add(self.gemini_radio)
        api_panel.add(self.groq_radio)
        
        # API keys
        key_panel = JPanel(FlowLayout())
        self.openai_key_field = JTextField(20)
        self.gemini_key_field = JTextField(20)
        self.groq_key_field = JTextField(20)
        key_panel.add(JLabel("OpenAI Key: "))
        key_panel.add(self.openai_key_field)
        key_panel.add(JLabel("Gemini Key: "))
        key_panel.add(self.gemini_key_field)
        key_panel.add(JLabel("Groq Key: "))
        key_panel.add(self.groq_key_field)
        
        # Model selection
        model_panel = JPanel(FlowLayout())
        self.model_combo = JComboBox([
            "OpenAI-gpt-3.5-turbo", 
            "Gemini-gemini-2.0-flash",
            "Groq-llama-3.3-70b-versatile",
            "Groq-openai/gpt-oss-20b",
            "Groq-meta-llama/llama-guard-4-12b"
        ])
        model_panel.add(JLabel("Model: "))
        model_panel.add(self.model_combo)
        
        # Max prompt size
        size_panel = JPanel(FlowLayout())
        self.size_field = JTextField("2048", 10)
        size_panel.add(JLabel("Max Prompt Size: "))
        size_panel.add(self.size_field)
        
        # Prompt textarea
        prompt_panel = JPanel(BorderLayout())
        self.prompt_area = JTextArea(10, 50)
        self.prompt_area.setText(self.prompt)
        prompt_scroll = JScrollPane(self.prompt_area)
        prompt_panel.add(JLabel("Custom Prompt:"), BorderLayout.NORTH)
        prompt_panel.add(prompt_scroll, BorderLayout.CENTER)
        
        # Save button
        save_button = JButton("Save Settings", actionPerformed=self.save_settings)
        prompt_panel.add(save_button, BorderLayout.SOUTH)
        
        # Assemble settings panel
        top_config_panel = JPanel(BorderLayout())
        top_config_panel.add(api_panel, BorderLayout.NORTH)
        top_config_panel.add(key_panel, BorderLayout.CENTER)
        
        center_config_panel = JPanel(BorderLayout())
        center_config_panel.add(model_panel, BorderLayout.WEST)
        center_config_panel.add(size_panel, BorderLayout.EAST)
        
        settings_container.add(top_config_panel, BorderLayout.NORTH)
        settings_container.add(center_config_panel, BorderLayout.CENTER)
        settings_container.add(prompt_panel, BorderLayout.SOUTH)

        # --- Bottom Panel (Results) ---
        results_container = JPanel(BorderLayout())
        
        # Results list (left) with context menu
        self.results_list = JList(self.results_list_model)
        self.results_list.setCellRenderer(FalsePositiveRenderer())
        self.results_list.addListSelectionListener(self.on_result_selected)
        self.results_list.addMouseListener(self.ResultListMouseListener(self))
        results_list_scroll = JScrollPane(self.results_list)
        
        # --- Report Detail View (Right) ---
        report_detail_panel = JPanel(BorderLayout())
        
        self.report_tabbed_pane = JTabbedPane()
        self.advisory_pane = JEditorPane("text/html", "")
        self.request_pane = JTextArea()
        self.response_pane = JTextArea()
        
        self.advisory_pane.setEditable(False)
        self.request_pane.setEditable(False)
        self.response_pane.setEditable(False)
        
        self.report_tabbed_pane.addTab("Advisory", JScrollPane(self.advisory_pane))
        self.report_tabbed_pane.addTab("Request", JScrollPane(self.request_pane))
        self.report_tabbed_pane.addTab("Response", JScrollPane(self.response_pane))
        
        false_positive_button = JButton("Mark as false positive", actionPerformed=self.mark_as_false_positive)
        
        report_detail_panel.add(self.report_tabbed_pane, BorderLayout.CENTER)
        report_detail_panel.add(false_positive_button, BorderLayout.SOUTH)
        
        # Split pane for list and detail
        results_split_pane = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, results_list_scroll, report_detail_panel)
        results_split_pane.setDividerLocation(250)
        
        results_container.add(JLabel("Analysis Results: (AI can make mistakes, so always double-check its responses)"), BorderLayout.NORTH)
        results_container.add(results_split_pane, BorderLayout.CENTER)

        # --- Main Split Pane ---
        self.main_split_pane = JSplitPane(JSplitPane.VERTICAL_SPLIT, settings_container, results_container)
        self.main_split_pane.setDividerLocation(400)
        
        self.settings_panel = self.main_split_pane
    
    def save_settings(self, event):
        if self.openai_radio.isSelected():
            self.api_choice = "OpenAI"
        elif self.gemini_radio.isSelected():
            self.api_choice = "Gemini"
        else:
            self.api_choice = "Groq"
            
        self.api_key_openai = self.openai_key_field.getText()
        self.api_key_gemini = self.gemini_key_field.getText()
        self.api_key_groq = self.groq_key_field.getText()
        self.model = self.model_combo.getSelectedItem()
        try:
            self.max_prompt_size = int(self.size_field.getText())
        except:
            self.max_prompt_size = 2048
        self.prompt = self.prompt_area.getText()
        
        stdout = self._callbacks.getStdout()
        if stdout:
            stdout.write("Settings saved: API=" + self.api_choice + ", Model=" + self.model + "\n")
    
    def get_settings_panel(self):
        return self.settings_panel
    
    def get_api_choice(self):
        return self.api_choice
    
    def get_api_key(self, api_choice):
        if api_choice == "OpenAI":
            return self.api_key_openai
        elif api_choice == "Gemini":
            return self.api_key_gemini
        else: # Groq
            return self.api_key_groq
    
    def get_model(self):
        # Return only the model name, without the provider prefix
        model_full_name = self.model_combo.getSelectedItem()
        if model_full_name.startswith("OpenAI-"):
            return model_full_name.split('-', 1)[1]
        elif model_full_name.startswith("Gemini-"):
            return model_full_name.split('-', 1)[1]
        elif model_full_name.startswith("Groq-"):
            return model_full_name.split('-', 1)[1]
        return model_full_name
    
    def get_max_prompt_size(self):
        return self.max_prompt_size
    
    def get_prompt(self):
        return self.prompt
    
    def _markdown_to_html(self, text):
        if not text:
            return ""
        html = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        
        # Convert Markdown to HTML
        html = re.sub(r'^# (.*)', r'<h1>\1</h1>', html, flags=re.MULTILINE)
        html = re.sub(r'^## (.*)', r'<h2>\1</h2>', html, flags=re.MULTILINE)
        html = re.sub(r'\*\*(.*?)\*\*', r'<b>\1</b>', html)
        
        # Handle lists more robustly
        lines = html.split('\n')
        in_list = False
        processed_lines = []
        for line in lines:
            stripped_line = line.strip()
            if stripped_line.startswith('* '):
                if not in_list:
                    processed_lines.append('<ul>')
                    in_list = True
                processed_lines.append('<li>' + stripped_line[2:] + '</li>')
            elif stripped_line.startswith('1. '): # Ordered lists
                if not in_list:
                    processed_lines.append('<ol>')
                    in_list = True
                processed_lines.append('<li>' + stripped_line[3:] + '</li>')
            else:
                if in_list:
                    processed_lines.append('</ul>' if not processed_lines[-1].startswith('<ol>') else '</ol>')
                    in_list = False
                processed_lines.append(line)
        
        if in_list:
            processed_lines.append('</ul>' if not processed_lines[-1].startswith('<ol>') else '</ol>')
            
        html = '<br>'.join(processed_lines).replace('<br><ul>', '<ul>').replace('</ul><br>', '</ul>')
        html = html.replace('<br><ol>', '<ol>').replace('</ol><br>', '</ol>')

        return "<html><body style='font-family: sans-serif; font-size: 12pt; margin: 5px;'>{}</body></html>".format(html)

    def add_placeholder_issue(self, url):
        display_name = "Analyzing... [" + url + "]"
        self.results_list_model.addElement(display_name)
        return self.results_list_model.getSize() - 1

    def update_issue(self, index, issue):
        display_name = issue.getIssueName() + " [" + issue.getUrl().toString() + "]"
        self.results_list_model.setElementAt(display_name, index)
        self.results_data[display_name] = issue

    def on_result_selected(self, event):
        if event and event.getValueIsAdjusting():
            return
            
        selected_name = self.results_list.getSelectedValue()
        if selected_name:
            self.current_issue = self.results_data.get(selected_name)
            if self.current_issue:
                # Populate Advisory
                advisory_html = self._markdown_to_html(
                    "# " + self.current_issue.getIssueName() + "\n" +
                    "**Severity:** " + self.current_issue.getSeverity() + "\n" +
                    "**Confidence:** " + self.current_issue.getConfidence() + "\n\n" +
                    "## Issue Detail\n" + self.current_issue.getIssueDetail() + "\n\n" +
                    "## Issue Background\n" + self.current_issue.getIssueBackground() + "\n\n" +
                    "## Remediation\n" + self.current_issue.getRemediationDetail()
                )
                self.advisory_pane.setText(advisory_html)
                
                # Populate Request/Response
                self.request_pane.setText(self._callbacks.getHelpers().bytesToString(self.current_issue.getHttpMessages()[0].getRequest()))
                self.response_pane.setText(self._callbacks.getHelpers().bytesToString(self.current_issue.getHttpMessages()[0].getResponse()))
                
                self.advisory_pane.setCaretPosition(0)
                self.request_pane.setCaretPosition(0)
                self.response_pane.setCaretPosition(0)

    def mark_as_false_positive(self, event):
        if self.current_issue:
            selected_index = self.results_list.getSelectedIndex()
            if selected_index != -1:
                display_name = self.results_list_model.getElementAt(selected_index)
                if not display_name.startswith("[False Positive]"):
                    new_name = "[False Positive] " + display_name
                    self.results_list_model.setElementAt(new_name, selected_index)
                    self.results_data[new_name] = self.results_data.pop(display_name)
                    self.results_list.repaint()

    def delete_result(self, index):
        if index >= 0:
            item = self.results_list_model.getElementAt(index)
            self.results_list_model.remove(index)
            if item in self.results_data:
                del self.results_data[item]
            self.result_detail_area.setText("")

    class ResultListMouseListener(MouseAdapter):
        def __init__(self, ui_instance):
            self.ui = ui_instance

        def mousePressed(self, e):
            self.showPopup(e)

        def mouseReleased(self, e):
            self.showPopup(e)

        def showPopup(self, e):
            if e.isPopupTrigger():
                list_comp = e.getComponent()
                index = list_comp.locationToIndex(e.getPoint())
                if index != -1:
                    list_comp.setSelectedIndex(index)
                    popup = JPopupMenu()
                    delete_item = JMenuItem("Delete")
                    delete_item.addActionListener(lambda x: self.ui.delete_result(index))
                    popup.add(delete_item)
                    popup.show(e.getComponent(), e.getX(), e.getY())
