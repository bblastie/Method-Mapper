from burp import IBurpExtender

class BurpExtender(IBurpExtender):  
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Method Mapper")
        print("Extension loaded successfully")
        self.access_sitemap()

    def getResponseHeadersandBody(self, content):
        response = content.getResponse()
        response_data = self._helpers.analyzeResponse(response)
        headers = list(response_data.getHeaders())
        body = response[response_data.getBodyOffset():].tostring()
        return headers, body

    def access_sitemap(self):
        self.sitemap = self._callbacks.getSiteMap("")
        for item in self.sitemap:
            http_service = item.getHttpService()
            request_info = self._helpers.analyzeRequest(http_service, item.getRequest())
            print("Request URL:", request_info.getUrl())       
