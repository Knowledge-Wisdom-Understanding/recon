# Debugging

## Enabling & Disabling Feature(s)

- Starting on line 321, The Various Service Scan/Enum Functions can be commented out to turn them off which will gracefully disable that feature.
- getOpenPorts() must always be left on for proper functionality.
- scanTop10000Ports() only needs to be on for the first scan of a new target.
- cmsEnum() is dependent on enumHTTP() and cmsEnumSSL() is dependent on enumHTTPS() and so on...
- sortFoundProxyUrls() is necessary for proxyEnumCMS() to work properly along with aquatone() which is dependent on both of the sortFoundUrls() and sortFoundkProxyUrls() functions.
- All the different Brute Forcing options other than SSH haven't been completed yet and will just print a message before exiting the program.
