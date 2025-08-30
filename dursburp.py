# DursBurp - AI-Powered Security Analysis for Burp Suite
#
# Author: Kang Ali
# Version: 1.0.0
# GitHub: https://github.com/roomkangali/DursBurp
#
# This extension integrates Large Language Models (LLMs) into Burp Suite to assist with security analysis.

from burp import IBurpExtender, IContextMenuFactory, ITab, IContextMenuInvocation
from java.io import PrintWriter
from java.util import ArrayList
from javax.swing import JMenuItem

# Import modules (assuming dursburp folder is in Folder for loading modules)
from scanner import Scanner
from ui import UI

class BurpExtender(IBurpExtender, IContextMenuFactory, ITab):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self.stdout = PrintWriter(callbacks.getStdout(), True) if hasattr(callbacks, 'getStdout') else None
        
        # Extension name
        callbacks.setExtensionName("DursBurp")
        
        # Initialize modules
        self.ui = UI(callbacks)
        self.scanner = Scanner(callbacks, self.ui)
        
        # Register components
        callbacks.registerContextMenuFactory(self)
        callbacks.addSuiteTab(self)
        
        # Log loading success
        if self.stdout:
            self.stdout.println("DursBurp loaded successfully!")
        else:
            print("DursBurp loaded successfully!")
    
    def getTabCaption(self):
        return "DursBurp"
    
    def getUiComponent(self):
        return self.ui.get_settings_panel()
    
    def createMenuItems(self, invocation):
        menu = ArrayList()
        
        # Check if the context is appropriate for adding the menu item
        if invocation.getInvocationContext() in [
            IContextMenuInvocation.CONTEXT_PROXY_HISTORY, 
            IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST, 
            IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST,
            IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_RESPONSE,
            IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_RESPONSE
        ]:
            if self.stdout:
                self.stdout.println("Creating context menu for invocation: " + str(invocation))
            else:
                print("Creating context menu for invocation: " + str(invocation))
            
            menu_item = JMenuItem("Analyze with DursBurp")
            menu_item.addActionListener(lambda x: self.scanner.analyze_single_request(invocation))
            menu.add(menu_item)
            
        return menu
