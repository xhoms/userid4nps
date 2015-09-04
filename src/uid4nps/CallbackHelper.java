/**
 * 
 */
package uid4nps;

import java.net.ProtocolException;
import java.util.TimerTask;

/**
 * Convenience TimerTask extension to avoid using anonymous classes inside {@link PANOSApiConnector} and {@link UseridPanosInterface}
 * 
 */
public class CallbackHelper extends TimerTask {
	
	/**
	 * {@link PANOSApiConnector} pointer in case we've been created to call back such a class type
	 */
	protected PANOSApiConnector panosApiCon = null;
	/**
	 * {@link UseridPanosInterface} pointer in case we've been created to call back such a class type
	 */
	protected UseridPanosInterface useridPanosInterface = null;

	/**
	 * Constructor to be used for callback to classes of type {@link PANOSApiConnector}
	 * 
	 * @param panosApiCon	The {@link PANOSApiConnector} class instance to be called
	 */
	public CallbackHelper(PANOSApiConnector panosApiCon) {
		this.panosApiCon = panosApiCon;
	}

	/**
	 * Constructor to be used for callback to classes of type {@link UseridPanosInterface}
	 * 
	 * @param useridPanosInterface	The {@link UseridPanosInterface} class instance to be called
	 */
	public CallbackHelper(UseridPanosInterface useridPanosInterface) {
		this.useridPanosInterface  = useridPanosInterface;
	}

	/* (non-Javadoc)
	 * @see java.util.TimerTask#run()
	 */
	@Override
	public void run() {
		if (panosApiCon != null)
			try {
				panosApiCon.checkConnection();
			} catch (ProtocolException e) {
			}
		else
			if(useridPanosInterface != null)
				useridPanosInterface.callBackTask();
	}

}
