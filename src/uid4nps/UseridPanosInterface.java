package uid4nps;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Timer;
import java.util.TimerTask;
import java.util.concurrent.Semaphore;
import java.util.logging.Logger;

import javax.xml.parsers.ParserConfigurationException;

import org.xml.sax.SAXException;

/**
 * This class behaves as a buffer. It prepares valid user-id entries and keeps the in the buffer until either
 * the buffer is full or the timer expires 
 *
 */
public class UseridPanosInterface {
	
	private TimerTask packUserIdEntries;
	private Timer tempo;
	/**
	 * This buffer will host temporary user-id login entries
	 */
	protected ArrayList <String []>pendLoginEntries; 
	/**
	 * This buffer will host temporary user-id logout entries 
	 */
	protected ArrayList <String []>pendLogoutEntries; 
	private Semaphore suTurno;
	/**
	 * Maximum number of valid user-id entries to keep in buffer before we decide to flush it
	 */
	protected int maxPendingEntries;
	/**
	 * The timeout in minutes that we'll use when building user-id login entries
	 */
	protected int useridTimeout;
	/**
	 * Maximum time in milliseconds we keep valid user-id entries in the buffer before we decide to flush it
	 */
	protected int panosBufferedTime;
	/**
	 * Flag to activate dynamic address object feature available in PANOS 6.0
	 */
	protected boolean dynAddressFeature;
	private Logger logHandler;	
	/**
	 * Pointer to the {@link PANOSApiConnector} handler for the first PANOS cluster member
	 */
	protected PANOSApiConnector PA1;
	/**
	 * Pointer to the {@link PANOSApiConnector} handler for the second PANOS cluster member
	 */
	protected PANOSApiConnector PA2;
	private PanosXlmResponseParse panosXmlResponse;
	private String response;
	
	/**
	 * Initializes the class fields
	 * 
	 * @param maxPendingEntries		How many valid user-id entries we can keep in buffer before flushing it
	 * @param useridTimeout			What user-id timeout value we'll put in the entries
	 * @param panosBufferedTime		How many milliseconds we can keep valid user-id entries in the buffer before flushing it
	 * @param dynAddressFeature		Flag to use the dynamic Address Object feature in PANOS 6.0
	 * @throws ParserConfigurationException
	 * @throws SAXException
	 */
	public UseridPanosInterface(int maxPendingEntries, int useridTimeout, int panosBufferedTime, boolean dynAddressFeature) throws ParserConfigurationException, SAXException {
		this.maxPendingEntries = maxPendingEntries;
		this.useridTimeout = useridTimeout;
		this.panosBufferedTime = panosBufferedTime;
		this.dynAddressFeature = dynAddressFeature;
		logHandler = Logger.getLogger("userid4nps");
		panosXmlResponse = new PanosXlmResponseParse();
		pendLoginEntries = new ArrayList<String[]>();
		pendLogoutEntries = new ArrayList<String[]>();
		tempo = new Timer();
		suTurno = new Semaphore(1);
		response = new String();
		packUserIdEntries = new CallbackHelper(this);
	}
	
	/**
	 * This is the method called by the TimerTask periodic timer
	 * It flushes the buffer provided there is any pending user-id entry available
	 */
	public void callBackTask ()
	{
		try {
			suTurno.acquire();
		} catch (InterruptedException e) {
			e.printStackTrace();
		}
		if (pendLoginEntries.size() + pendLogoutEntries.size() > 0) {
			String returnMessage;
			returnMessage = flushEntries();
			try {
				parseUserIdApiResponse(returnMessage);
			} catch (IOException e) {
			}
		}
		suTurno.release();
	}
	
	/**
	 * Initializes {@link UseridPanosInterface#PA1}
	 * 
	 * @param URL		A valid URL to a PANOS device (without the tailing "/api")
	 * @param ApiKey	The API key to be used when authenticating with this PANOS device
	 * @throws IOException
	 */
	public void setPanosApiC1 (String URL, String ApiKey, String vsys) throws IOException {
		PA1 = new PANOSApiConnector(URL, ApiKey, vsys);
	}

	/**
	 * Initializes {@link UseridPanosInterface#PA2}
	 * 
	 * @param URL		A valid URL to a PANOS device (without the tailing "/api")
	 * @param ApiKey	The API key to be used when authenticating with this PANOS device
	 * @throws IOException
	 */
	public void setPanosApiC2 (String URL, String ApiKey, String vsys) throws IOException {
		PA2 = new PANOSApiConnector(URL, ApiKey, vsys);
	}
	
	/**
	 * A convenience method to get the {@link PANOSApiConnector} for the first PANOS device in the cluster.
	 * It will be probably used to call its graceful shutdown methods
	 * 
	 * @return	the {@link PANOSApiConnector} object for the first PANOS device in the cluster
	 */
	public PANOSApiConnector getPanosApiC1() {
		return PA1;
	}

	/**
	 * A convenience method to get the {@link PANOSApiConnector} for the second PANOS device in the cluster.
	 * It will be probably used to call its graceful shutdown methods
	 * 
	 * @return	the {@link PANOSApiConnector} object for the second PANOS device in the cluster
	 */
	public PANOSApiConnector getPanosApiC2() {
		return PA2;
	}

	/**
	 * Starts this instance periodic timer to check valid entries in the buffer
	 */
	public void startTimer () {
		tempo.schedule(packUserIdEntries, 0, panosBufferedTime);		
	}
	
	/**
	 * Stops the timer. For graceful shutdown procedures
	 */
	public void stopTimer() {
		tempo.cancel();
	}
	
	/**
	 * It adds a valid user-id entry in the corresponding (login/logout) buffer
	 * 
	 * @param AcctStatusType	"1" means it is an START type of message
	 * @param UserName			Username to be used in the user-id XML message
	 * @param FramedIPAddress	IP address to be used in the user-id XML message
	 * @param NASIdentifier		String with the NAS Identifier. If it is not null it will create a tagged dynamic address object
	 * @throws IOException
	 */
	public void addEntry(String AcctStatusType, String UserName, String FramedIPAddress, String NASIdentifier) throws IOException {
		String [] entry = { UserName, FramedIPAddress, NASIdentifier };
		logHandler.fine("Buffering new entry ("+AcctStatusType+";"+UserName+";"+FramedIPAddress+")");
		try {
			suTurno.acquire();
		} catch (InterruptedException e) {
			e.printStackTrace();
		}
		removeDuplicateEntries(entry);
		if (AcctStatusType.equals("1") || AcctStatusType.equals("3")) {
			pendLoginEntries.add(entry);
		}
		else { 
			pendLogoutEntries.add(entry);
		}
		if(pendLoginEntries.size() + pendLogoutEntries.size() == maxPendingEntries) {
			String returnMessage;
			returnMessage = flushEntries();
			parseUserIdApiResponse(returnMessage);
		}
		suTurno.release();
	}
	
	/**
	 * Looks for a given entry in the pending login buffer
	 * 
	 * @param bufferSize	The size of the buffer
	 * @param entry		The entry we're looking in the pending entry buffer
	 * @return			The index in the login buffer to the element containing the entry we're looking for.
	 * 					If the return value equals to the size of the buffer then it means the entry doesn't exist
	 */
	protected int loginEntryExists( String[] entry, int bufferSize) {
		int a;
		for (a=0; a < bufferSize; a++) {
			String[] currentEntry = pendLoginEntries.get(a);
			if (currentEntry[0].equals(entry[0]) && currentEntry[1].equals(entry[1]))
				return a;
		}
		return a;
	}

	/**
	 * Looks for a given entry in the pending logout buffer
	 * 
	 * @param bufferSize	The size of the buffer
	 * @param entry		The entry we're looking in the pending entry buffer
	 * @return			The index in the logout buffer to the element containing the entry we're looking for.
	 * 					If the return value equals to the size of the buffer then it means the entry doesn't exist
	 */
	protected int logoutEntryExists( String[] entry, int bufferSize) {
		int a;
		for (a=0; a < bufferSize; a++) {
			String[] currentEntry = pendLogoutEntries.get(a);
			if (currentEntry[0].equals(entry[0]) && currentEntry[1].equals(entry[1]))
				return a;
		}
		return a;
	}
	
	/**
	 * Provided a given entry we'll remove any existing duplicated in the login of logout buffer.
	 * 
	 * @param entry		Entry to be looked at the buffers for duplicates
	 */
	protected void removeDuplicateEntries(String[] entry)
	{
		int loginBufferSize = pendLoginEntries.size();
		int logoutBufferSize = pendLogoutEntries.size();
		int duplicatedLoginIndex = loginEntryExists(entry, loginBufferSize);
		int duplicatedLogoutIndex = logoutEntryExists(entry, logoutBufferSize);
		if (duplicatedLoginIndex != loginBufferSize) {
			pendLoginEntries.remove(duplicatedLoginIndex);
			logHandler.fine("Removed duplicated login entry already in the buffer");
			}
		if (duplicatedLogoutIndex != logoutBufferSize) {
			pendLogoutEntries.remove(duplicatedLogoutIndex);
			logHandler.fine("Removed duplicated logout entry already in the buffer");
		}
	}

	/**
	 * Flushes the buffer to the first available {@link PANOSApiConnector} device
	 *  
	 * @return	The XML response message received by the PANOS device. NULL means we've been unable to send the buffer to any PANOS device
	 */
	protected String flushEntries() {
		response = "";
		String xmlMessage = "<uid-message><version>1.0</version><type>update</type><payload><login>";
		for (String[] entry : pendLoginEntries)
			xmlMessage+=String.format("<entry name=\"%s\" ip=\"%s\" timeout=\"%d\" />", entry[0], entry[1], useridTimeout);
		xmlMessage+="</login><logout>";
		for (String[] entry : pendLogoutEntries)
			xmlMessage+=String.format("<entry name=\"%s\" ip=\"%s\" />", entry[0], entry[1] );
		xmlMessage+="</logout>";
		if (dynAddressFeature) {
			xmlMessage+="<register>";
			for (String[] entry : pendLoginEntries)
				if (entry[2]!=null)
					xmlMessage+=String.format("<entry ip=\"%s\"><tag><member>%s</member></tag></entry>", entry[1], entry[2] );
			xmlMessage+="</register><unregister>";
			for (String [] entry : pendLogoutEntries)
				if (entry[2]!=null)
					xmlMessage+=String.format("<entry ip=\"%s\"></entry>", entry[1] );
			xmlMessage+="</unregister>";
		}
		xmlMessage+="</payload></uid-message>";
		logHandler.fine("Flushing entries ("+pendLoginEntries.size()+";"+pendLogoutEntries.size()+")");
		pendLoginEntries.clear();
		pendLogoutEntries.clear();
		try {
			if (PA1.ready) 
				response = PA1.sendUserIdMessage(xmlMessage);
			if (!PA1.ready && PA2.ready)
				response = PA2.sendUserIdMessage(xmlMessage);
			if (!PA1.ready && !PA2.ready) {
				logHandler.warning("No PANOS device available to handle this update. Discarding");
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		return response;
	}
	
	/**
	 * Parses the XML response received by the PANOS device after we've called the user-id message
	 * 
	 * @param response		The XML PANOS response message
	 * @throws IOException
	 */
	protected void parseUserIdApiResponse(String response) throws IOException {
		if ( !response.equals(""))
			if (!panosXmlResponse.panosResponseParse(response)) {
				logHandler.warning("PANOS API response includes an error message");
				logHandler.fine(response);
			}
	}

}
