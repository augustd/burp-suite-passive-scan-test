package burp;

import java.net.URL;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Simple test of whether passive scan checks are run on every active scan
 * response
 *
 * @author August Detlefsen [augustd at codemagi dot com]
 */
public class BurpExtender implements IBurpExtender, IScannerCheck {

	protected IBurpExtenderCallbacks callbacks;
	protected IExtensionHelpers helpers;
	
	protected HashMap<String,Integer> passiveCount = new HashMap<>();
	protected HashMap<String,Integer> activeCount = new HashMap<>();

	@Override
	public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {
		// keep a reference to our callbacks object
		this.callbacks = callbacks;

		// obtain an extension helpers object
		helpers = callbacks.getHelpers();

		// set our extension name
		callbacks.setExtensionName("Passive scan test");

		// register the extension as a custom scanner check
		callbacks.registerScannerCheck(this);
	
		callbacks.printOutput("Loaded passive scan test " + callbacks.getExtensionFilename());
	}

	@Override
	public List<IScanIssue> doPassiveScan(IHttpRequestResponse ihrr) {
		//get the URL of the requst
		URL url = helpers.analyzeRequest(ihrr).getUrl();
		callbacks.printOutput("Doing passive scan: " + url.toString());
		
		int count = incrementCount(passiveCount, url.toString());

		callbacks.printOutput("PASSIVE: count: " + count + " " + url.toString());

		return new ArrayList<>();
	}

	@Override
	public List<IScanIssue> doActiveScan(IHttpRequestResponse ihrr, IScannerInsertionPoint isip) {
		//get the URL of the requst
		URL url = helpers.analyzeRequest(ihrr).getUrl();
		callbacks.printOutput("Doing active scan: " + url.toString());
		
		int count = incrementCount(activeCount, url.toString());

		callbacks.printOutput("ACTIVE: count: " + count + " " + url.toString());

		return new ArrayList<>();
	}

	private int incrementCount(Map<String,Integer> counter, String url) {
		int count = 1;
		if (counter.containsKey(url)) {
			count = counter.get(url);
			count++;
			counter.put(url, count);
		} else {
			counter.put(url, 1);
		}
		return count;
	}
	
	@Override
	public int consolidateDuplicateIssues(IScanIssue isi, IScanIssue isi1) {
		return 0;
	}

}
