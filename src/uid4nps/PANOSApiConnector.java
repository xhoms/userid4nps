package uid4nps;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.ProtocolException;
import java.net.URL;
import java.net.URLEncoder;
import java.util.Timer;
import java.util.TimerTask;
import java.util.logging.Logger;

/**
 * This class hosts all methods and fields needed to keep the API connection opened with the PANOS device
 * After the constructor has initialized all fields, the consumer must call the {@link PANOSApiConnector#startTimer}
 * before any call to {@link PANOSApiConnector#sendUserIdMessage}
 *
 */
public class PANOSApiConnector {
	/**
	 * Url of the PANOS device where the resorce "/api" can be found
	 */
	protected URL PANOSUrl;
	/**
	 * API key to be used against this device as authentication
	 */
	protected String APIKey;
	/**
	 * Target vsys for the userid message. We'll discard this attribute in case it is equal to "none"
	 */
	protected String vsys;
	private HttpURLConnection APIConnection;
	/**
	 * A flag that marks this PANOS targeted device ready to receive user-id messages
	 */
	public Boolean ready;
	public Boolean giveUp;
	private Logger logHandler;
	private Timer tempo;
	/**
	 * {@link TimerTask} field that calls the {@link PANOSApiConnector#checkConnection} method from within its {@link TimerTask#run} method
	 */
	protected String xmlResult;
	private String inputLine;
	private String linia;
	private String response;
	private DataOutputStream wr;
	private BufferedReader in;
	/**
	 * This field will contain the keepalive check command ("check pending-changes")
	 */
	protected String panosCheckCommand;
	private CallbackHelper cbHelp;
	private String urlParameters;
	
	/**
	 * Constructor method
	 * @param pANOSUrl		A string representation of the way to reach the PANOS API (without the tailing "/api")
	 * @param aPIKey		The PANOS authorization key for this device (get it with a type=keygen API call) 
	 * @throws IOException
	 */
	public PANOSApiConnector(String pANOSUrl, String aPIKey, String vsys) throws IOException {
		PANOSUrl = new URL(pANOSUrl+"/api/?");
		APIKey = aPIKey;
		this.vsys=vsys;
		panosCheckCommand = "type=op&key="+APIKey+"&cmd="+URLEncoder.encode("<check><pending-changes></pending-changes></check>", "utf-8");
		logHandler = Logger.getLogger("userid4nps");
		giveUp = false;
	}
	
	/**
	 * Method to check the successful connection with the PANOS device
	 * First we check if we've been requested to giveUp (called the {@link userid4nps#stop} method in the main class).
	 * In such a case we just return. Otherwise we'll send the {@link PANOSApiConnector#panosCheckCommand} to the device
	 * to check if it produces a valid response.
	 * <p>
	 * If there is any communications exception during the check, a 1 minute timer will be started to check the connection and the {@link PANOSApiConnector#ready} flag will be cleared
	 * <p>
	 * If we get a valid response we cancel the timer and raise the {@link PANOSApiConnector#ready} flag  
	 * @throws ProtocolException 
	 */
	public void checkConnection() throws ProtocolException {
		if (giveUp)
			tempo.cancel();
		else {
			try {
				APIConnection = (HttpURLConnection) PANOSUrl.openConnection();
			} catch (IOException e) {
				logHandler.info("Communication error. Alive Check Failed for "+PANOSUrl.toString());
				return;
			}
			APIConnection.setDoOutput(true);
			APIConnection.setDoInput(true);
			APIConnection.setRequestMethod("POST"); 
			APIConnection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded"); 
			APIConnection.setRequestProperty("charset", "utf-8");
			APIConnection.setUseCaches (false);
			APIConnection.setRequestProperty("Content-Length", "" + Integer.toString(panosCheckCommand.getBytes().length));
			logHandler.finest(panosCheckCommand);
			try {
				wr = new DataOutputStream(APIConnection.getOutputStream ());
				wr.writeBytes(panosCheckCommand);
				wr.flush();
				wr.close();
			} catch (IOException e) {
				logHandler.info("Communication error. Alive Check Failed for "+PANOSUrl.toString());
				return;
			}
			try {
				in = new BufferedReader(new InputStreamReader(APIConnection.getInputStream()));
				response = "";
				while ((linia = in.readLine()) != null)
					response += linia;
				in.close();
				logHandler.finest("Response message: "+response);
			} catch (IOException e) {
				logHandler.info("Communication error. Alive Check Failed for "+PANOSUrl.toString());
				return;
			}
			if (response.contains("success")) {
				logHandler.info("Alive Check Succeded for "+PANOSUrl.toString());
				tempo.cancel();
				ready = true;
			}
			else
				logHandler.info("Non success message received by "+PANOSUrl.toString());
		}
	}
	
	/**
	 * This method creates a 1 minute periodic timer to keep checking the connection with the PANOS device.
	 * The {@link TimerTask} field will call the {@link PANOSApiConnector#checkConnection} method when triggered
	 * 
	 * @param reason	The message that will be logged at INFO level as the reason.
	 */
	public void startTimer(String reason) {
		ready = false;
		tempo = new Timer();		
		cbHelp = new CallbackHelper(this);
		logHandler.info(reason);
		tempo.schedule(cbHelp, 0, 60000);
		logHandler.fine("Starting the checkConnectionTimer with "+PANOSUrl.toString());
	}

	/**
	 * This method will send a correctly formated PANOS User-ID XML message to this PANOS device.
	 * We don't check the integrity of the message.
	 * <p>
	 * In case of communications exception, we'll call {@link PANOSApiConnector#startTimer}
	 * to mark this device as non-functional and to start the checking timer 
	 * 
	 * @param command	XML user-id message to be sent to this PANOS device
	 * @return			the XML response message received from the PANOS device or null is case of communication error
	 * @throws ProtocolException
	 * @throws UnsupportedEncodingException
	 */
	public String sendUserIdMessage(String command) throws ProtocolException, UnsupportedEncodingException {
		xmlResult = "";
		if (vsys.equals("none"))
			urlParameters = "type=user-id&action=set&key="+APIKey+"&cmd="+URLEncoder.encode(command, "utf-8");
		else
			urlParameters = "type=user-id&vsys="+vsys+"&action=set&key="+APIKey+"&cmd="+URLEncoder.encode(command, "utf-8");
		logHandler.fine(urlParameters);
		try {
			APIConnection = (HttpURLConnection) PANOSUrl.openConnection();
		} catch (IOException e) {
			startTimer("Lost connection with the PANOS devicer "+PANOSUrl.toString());
			return xmlResult;
		}
		APIConnection.setDoOutput(true);
		APIConnection.setDoInput(true);
		APIConnection.setRequestMethod("POST"); 
		APIConnection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded"); 
		APIConnection.setRequestProperty("charset", "utf-8");
		APIConnection.setUseCaches (false);
		APIConnection.setRequestProperty("Content-Length", "" + Integer.toString(urlParameters.getBytes().length));
		try {
			wr = new DataOutputStream(APIConnection.getOutputStream ());
			wr.writeBytes(urlParameters);
			wr.flush();
			wr.close();
		} catch (IOException e) {
			startTimer("Lost connection with the PANOS devicer "+PANOSUrl.toString());
			return xmlResult;
		}
		try {
			in = new BufferedReader(new InputStreamReader(APIConnection.getInputStream()));
			while ((inputLine = in.readLine()) != null)
				xmlResult+=inputLine;
			in.close();
		} catch (IOException e) {
			startTimer("Lost connection with the PANOS devicer "+PANOSUrl.toString());
			return xmlResult;
		}
		logHandler.fine(xmlResult);
		return xmlResult;
		}
	
	/**
	 * @return	the {@link Timer} field so it can be cancelled from outside the class
	 */
	public Timer getTempo () {
		return tempo;
	}
	
	/**
	 * Class to be called to graceful close all the resources
	 * 
	 * @throws IOException
	 */
	public void close() throws IOException {
		APIConnection.disconnect();
	}
}
