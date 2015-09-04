package uid4nps;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.channels.Channels;
import java.nio.channels.FileChannel;
import java.nio.file.DirectoryStream;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileTime;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Properties;
import java.util.logging.FileHandler;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.xml.parsers.ParserConfigurationException;
import org.xml.sax.SAXException;


/**
 * Main UserID connector for NPS accounting logs class
 *
 */
/**
 * @author apple
 *
 */
/**
 * @author apple
 *
 */
/**
 * @author apple
 *
 */
public class userid4nps {
	
	/**
	 * Path to configuration path. Its value must be passed from the command line as "-config=<configurationFile>"
	 */
	protected static String configFile;
	/**
	 * Path to the file that will host the log messages we generate. It equals the "outputLogFile"
	 * parameter in the configuration file and defaults to "userid4nps.log" 
	 */
	protected static String outputLogFile;
	/**
	 * It equals the "logLevel" parameter in the configuration file.
	 * Use INFO for normal operation, FINE for tracing and FINEST for debugging
	 */
	protected static Level logLevel;
	/**
	 * How many user-id requests we may buffer before sending all of them to the PANOS device.
	 * It equals the "maxPendingEntries" in the configuration file and defaults to 100
	 */
	protected static int maxPendingEntries;
	/**
	 * User-ID timeout (in minutes) we'll use when pushing entries to the PANOS device.
	 * It is safe to use a long timeout as we'll clear the entry provided we receive an
	 * Accounting-Stop message for this user.
	 * It equals the "useridTimeout" in the configuration file and defaults to 1440
	 */
	protected static int useridTimeout;
	/**
	 * How many milliseconds we'll keep user-id requests in the buffer before we flush
	 * the buffer to the PANOS device.
	 * It equals the "panosBufferedTime" in the configuration file and defaults to 2000
	 */
	protected static int panosBufferedTime;
	/**
	 * Domain name that will be added to all valid accounting records that do not have
	 * a valid domain name. It equals the "defaultDomain" in the configuration file and defaults to "corppro"
	 */
	protected static String defaultDomain;
	/**
	 * URL path to reach the first PANOS cluster member.
	 * It equals the "fw1Url" in the configuration file and defaults to "https://192.168.1.1".
	 * Be aware that the colon ":" char must be escaped in the configuration file
	 */
	protected static String fw1Url;
	/**
	 * URL path to reach the second PANOS cluster member.
	 * It equals the "fw2Url" in the configuration file and defaults to "https://192.168.1.2"
	 * It is save to use the same value as "fw1Url" in single node scenarios or when using an
	 * inband management interface for both cluster members
	 */
	protected static String fw2Url;
	/**
	 * API key for the first PANOS cluster member. It can be obtained with the keygen PANOS API type.
	 * (consult PANOS API reference guide for more information).
	 * It equals the "fw1PanosKey" in the configuration file and defaults to "0000"
	 */
	protected static String fw1PanosKey;
	/**
	 * API key for the second PANOS cluster member. It can be obtained with the keygen PANOS API type.
	 * It equals the "fw2PanosKey" in the configuration file and defaults to "0000"
	 */
	protected static String fw2PanosKey;
	/**
	 * Path to the directory where the DTS-compliant log entries from the NPS are stored.
	 * This directory must be used EXCLUSIVELLY for NPS DTS-compliant file storage.
	 * The log files must have a ".log" extension.
	 * It equals the "npsLogDir" in the configuration file and defaults to "C:/Windows/System32/LogFiles" 
	 */
	protected static String npsLogDir;
	/**
	 * Target vsys for the PANOS user-id messages. If vsys = "none" we'll not send the vsys attribute
	 * in the PANOS call. Otherwise we'll append vsys=<vsys> in the attribute chain
	 */
	protected static String vsys;
	/**
	 * This pattern will be matched against all NPS records. Only the ones matching this pattern will be included
	 * for processing
	 */
	protected static String includePattern;
	/**
	 * Boolean attribute to user PANOS 6.0 Tagged Dynamic Address features. If enabled we'll send dynamic address
	 * objects tagged with the string provided by the NAS device in the DTS field named "NAS-Identifier"
	 */
	protected static boolean dynAddressFeature;
	private static Logger logHandler;
	private static int currentState = Const.INIT;
	private static Path currentNpsLogFile = null;
	
	private static HashMap<Path,Long> currentFileSizeDB ;
	private static HashMap<Path,Long> oldFileSizeDB ;

	/**
	 * This field will point to the current NPS log file being used
	 */
	protected static FileChannel fcNpsLogFile;
	private static UseridNpsDtsParser parser;
	private static UseridPanosInterface paInterface;
	private static BufferedReader in;
	private static String xmlElement;
	private static int readlineTries = 0;
	private static FileSystem fs;
	private static Path npsLogPath;
	/**
	 * Field that, while true, will keep the FSM running ({@link userid4nps#fsm})
	 * Calling the class' {@link userid4nps#stop} method clears the value an eventually will break the main loop.
	 */
	protected static Boolean keepRunning = true;
	private static DirectoryStream<Path> npsDirStream;
	private static ArrayList<Path> unknownFileArray;
	
	/**
	 * Main method. It is invoked is run as a standalone application. A command line argument must
	 * be passed with the "-config=<configfile>" declaration. A simple wrapper to the {@link userid4nps#start} method
	 * 
	 * @param args		Command line arguments. Mandatory a "-config=<configfile>" argument
	 * @throws InterruptedException 
	 * @throws IOException 
	 * @throws ParserConfigurationException 
	 * @throws SAXException 
	 * @throws NoSuchAlgorithmException 
	 * @throws KeyManagementException 
	 */
	public static void main(String[] args) throws ParserConfigurationException, IOException, InterruptedException, SAXException, KeyManagementException, NoSuchAlgorithmException {	
		start(args);
	}
	
	/**
	 * The method starting the application. Parses the command line argument and starts
	 * the Finite State Machine ({@link userid4nps#fsm}) in the "INIT" state
	 * 
	 * @param args		Command line arguments. Mandatory a "-config=<configfile>" argument
	 * @throws ParserConfigurationException
	 * @throws IOException
	 * @throws InterruptedException
	 * @throws SAXException
	 * @throws KeyManagementException
	 * @throws NoSuchAlgorithmException
	 */
	public static void start(String[] args) throws ParserConfigurationException, IOException, InterruptedException, SAXException, KeyManagementException, NoSuchAlgorithmException {
		
		if (args.length != 1)
			System.out.print(Const.cmdLineError);
		else
		{
			String parts[] = args[0].split("=");
			if (parts.length != 2)
				System.out.print(Const.cmdLineError);
			else {
				if (!parts[0].equals("-config"))
					System.out.print(Const.cmdLineError);
				else {
					configFile = parts[1];
					fsm(Const.INIT);
				}
			}
		}
	}
	
	/**
	 * Clears the {@link userid4nps#keepRunning} flag so {@link userid4nps#fsm} can gracefully end
	 * 
	 * @param args		Unused
	 */
	public static void stop(String[] args) {
		logHandler.fine("Called stop method. We'll try to graceful shutdown");
		keepRunning = false;
	}
		
	/**
	 * Initializes all class fields either from parsing the configuration file passed as command line argument
	 * or by initializing its values to their default value.
	 * In case the configuration file doesn't exist it will be created with default values (template).
	 * It is called from within the {@link userid4nps#fsm} when entering the INIT state.
	 * 
	 * @throws NoSuchAlgorithmException
	 * @throws KeyManagementException
	 * @throws IOException
	 * @throws ParserConfigurationException
	 * @throws SAXException
	 * @throws InterruptedException
	 */
	protected static void init () throws NoSuchAlgorithmException, KeyManagementException, IOException, ParserConfigurationException, SAXException, InterruptedException {
		Properties defaultProps = new Properties();
		defaultProps.put("maxPendingEntries", "100");
		defaultProps.put("useridTimeout", "1440");
		defaultProps.put("panosBufferedTime", "2000");
		defaultProps.put("defaultDomain", "corppro");
		defaultProps.put("fw1Url", "https://192.168.1.1");
		defaultProps.put("fw2Url", "https://192.168.1.2");
		defaultProps.put("fw1PanosKey", "0000");
		defaultProps.put("fw2PanosKey", "0000");
		defaultProps.put("vsys", "none");
		defaultProps.put("includePattern", ".*");
		defaultProps.put("outputLogFile", "userid4nps.log");
		defaultProps.put("logLevel", "INFO");
		defaultProps.put("npsLogDir", "C:/Windows/System32/LogFiles");
		defaultProps.put("dynAddressFeature","false");
		
		Properties runningParams = new Properties(defaultProps);
		FileInputStream configFileIs;
		try {
			configFileIs = new FileInputStream(configFile);
			runningParams.load(configFileIs);
			configFileIs.close();
		} catch (FileNotFoundException e1) {
			FileOutputStream configFileOs = new FileOutputStream(configFile);
			defaultProps.store(configFileOs, "Default values");
			configFileOs.close();
		}
		maxPendingEntries = Integer.valueOf(runningParams.getProperty("maxPendingEntries"));
		useridTimeout = Integer.valueOf(runningParams.getProperty("useridTimeout"));
		panosBufferedTime = Integer.valueOf(runningParams.getProperty("panosBufferedTime"));
		defaultDomain = runningParams.getProperty("defaultDomain");
		outputLogFile = runningParams.getProperty("outputLogFile");
		fw1Url = runningParams.getProperty("fw1Url");
		fw2Url = runningParams.getProperty("fw2Url");
		fw1PanosKey = runningParams.getProperty("fw1PanosKey");
		fw2PanosKey = runningParams.getProperty("fw2PanosKey");
		vsys = runningParams.getProperty("vsys");
		includePattern = runningParams.getProperty("includePattern");
		npsLogDir = runningParams.getProperty("npsLogDir");
		dynAddressFeature = runningParams.getProperty("dynAddressFeature").equals("true") ? true : false;
		try {
			logLevel = Level.parse(runningParams.getProperty("logLevel"));
		} catch (IllegalArgumentException e) {
			logLevel = Level.WARNING;
		}
		logHandler = Logger.getLogger("userid4nps");
		FileHandler fileHandler = new FileHandler(outputLogFile,true);
		SimpleFormatter sf = new SimpleFormatter();
		fileHandler.setFormatter(sf);
		logHandler.addHandler(fileHandler);
		logHandler.setLevel(logLevel);		
		logHandler.fine("userid4nps starting");
		currentNpsLogFile = null;
		fs = FileSystems.getDefault();
		npsLogPath = fs.getPath(npsLogDir);
		currentFileSizeDB = new HashMap<Path, Long>();
		oldFileSizeDB = new HashMap<Path, Long>();
		unknownFileArray = new ArrayList<Path>();
		parser = new UseridNpsDtsParser(defaultDomain, includePattern);
//		This block configures JVM to ignore SSL Cert issues
		TrustManager[] trustAllCerts = new TrustManager[] {new X509TrustManager() {

			@Override
			public void checkClientTrusted(X509Certificate[] arg0, String arg1)
					throws CertificateException {
			}

			@Override
			public void checkServerTrusted(X509Certificate[] arg0, String arg1)
					throws CertificateException {
			}

			@Override
			public X509Certificate[] getAcceptedIssuers() {
				return null;
			}
			}
		};
		SSLContext sc = SSLContext.getInstance("SSL");
		sc.init(null, trustAllCerts, new java.security.SecureRandom());
		HostnameVerifier allHostsValid = new HostnameVerifier() {

			@Override
			public boolean verify(String arg0, SSLSession arg1) {
				return true;
			}
			
		};
		HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
		HttpsURLConnection.setDefaultHostnameVerifier(allHostsValid);
		
		paInterface = new UseridPanosInterface(maxPendingEntries, useridTimeout, panosBufferedTime, dynAddressFeature);
		paInterface.setPanosApiC1(fw1Url, fw1PanosKey, vsys);
		paInterface.setPanosApiC2(fw2Url, fw2PanosKey, vsys);
		paInterface.getPanosApiC1().startTimer("Initial connection check");
		paInterface.getPanosApiC2().startTimer("Initial connection check");
		logHandler.fine("Staring flushing timer");		
		paInterface.startTimer();
	}
	
	/**
	 * A new line has been made available at the end of the {@link userid4nps#fcNpsLogFile} log file.
	 * We read the line from the file and call the XML parser.
	 * It is called from within the {@link userid4nps#fsm} each time it enters in the LINEPROC state.
	 * 
	 * @throws IOException
	 */
	protected static void lineProc() throws IOException {
		if (parser.IMIParser(xmlElement)) {
			logHandler.finest("Got a valid DTS entry. Sending it to the PanosInterface");
			paInterface.addEntry(parser.AcctStatusType,parser.UserName, parser.FramedIPAddress, parser.NASIdentifier);
		}
		else {
			logHandler.finest("Ignoring DTS entry read from file");
		}
	}
	
	/**
	 * After ten unsuccessful consecutive tries to read a new line from the {@link userid4nps#fcNpsLogFile}
	 * we'll review the {@link userid4nps#npsLogDir} directory to see if NPS has rolled up to a new
	 * log file. In such a case we close the old fine and open {@link userid4nps#fcNpsLogFile} to the newer one.
	 * 
	 * @param oldFile	Pointer to the currently opened log file
	 * @return		A {@link userid4nps#fsm} OK transition.
	 * @throws IOException
	 */
	protected static int tryNewFile(Path oldFile) throws IOException {
		BasicFileAttributes attrs;
		FileTime timeLatest = null;
		Path latest = null;
		Boolean changeMade = false;
//		We've been provided an oldFile. Let's start with it.
		if (oldFile != null) {
			latest = oldFile;
			timeLatest = Files.readAttributes(latest, BasicFileAttributes.class).lastModifiedTime();
		}

//		Now time to get the latest entry in the directory
		npsDirStream = Files.newDirectoryStream(npsLogPath,"*.log");
		currentFileSizeDB.clear();
		for (Path fil: npsDirStream ) {
			attrs = Files.readAttributes(fil, BasicFileAttributes.class );
			FileTime entryPathModTime = attrs.lastModifiedTime();
			currentFileSizeDB.put(fil, attrs.size()); // This creates a database with current paths and sizes
			if ( timeLatest == null ) {
				logHandler.finest("First time: we'll start with '"+fil.getFileName()+"'");
				timeLatest = entryPathModTime;
				latest = fil;
				changeMade=true;
			} else {
//				I want to ignore the file if it is equal to oldFile
				if (oldFile != null)
					if (oldFile.equals(fil))
						continue;
				if (entryPathModTime.compareTo(timeLatest) > 0) {
					logHandler.finest("Newer file found: now evaluating '"+fil.getFileName()+"'");
					timeLatest = entryPathModTime;
					latest = fil;
					changeMade = true;
				}
			}
		}
		npsDirStream.close();

//		Options:
//		- oldFile = null : We must open latest file and position the reading pointer at the end of the file
//		- oldFile != null && changeMade: We must close old file and open new one from the beginning
		if (changeMade) {
			if (oldFile != null) {
				logHandler.info("New log file detected: closing '"+currentNpsLogFile.getFileName()+"'");
				in.close();
				fcNpsLogFile.close();
			}
			logHandler.info("Opening log file '"+latest.getFileName()+"'");
			currentNpsLogFile = latest;
			fcNpsLogFile = FileChannel.open(currentNpsLogFile, StandardOpenOption.READ);
			in = new BufferedReader(Channels.newReader(fcNpsLogFile, "UTF-8"));
			if (oldFile == null) {
				logHandler.info("Positioning at the end of the log file '"+latest.getFileName()+"'");
				fcNpsLogFile.position(fcNpsLogFile.size());
			}
			oldFileSizeDB.clear();
			oldFileSizeDB.putAll(currentFileSizeDB);
			return Const.OK;
		}
		else {
			if (oldFile == null) {
				logHandler.warning("No log files available in the directory. Will wait 30 seconds");
				return Const.SLEEP;
			}
			else {
				logHandler.fine("Unable to sense changes by file timestamp. Let's try strategy 2: previously unknown .log file in the directory");
				unknownFileArray.clear();
				for (Path fil: currentFileSizeDB.keySet() ) {
					if(!oldFileSizeDB.containsKey(fil))
						unknownFileArray.add(fil);
				}
				if (unknownFileArray.size() == 1) {
					logHandler.info("Found a unique new .log file in the directory. This must be the newest one");
					logHandler.info("New log file detected: closing '"+currentNpsLogFile.getFileName()+"'");
					in.close();
					fcNpsLogFile.close();
					latest=unknownFileArray.get(0);
					currentNpsLogFile = latest;
					fcNpsLogFile = FileChannel.open(currentNpsLogFile, StandardOpenOption.READ);
					in = new BufferedReader(Channels.newReader(fcNpsLogFile, "UTF-8"));
					logHandler.info("Opening log file '"+latest.getFileName()+"'");
					oldFileSizeDB.clear();
					oldFileSizeDB.putAll(currentFileSizeDB);
					return Const.OK;
				}
				else {
					if (unknownFileArray.size() > 1) {
						logHandler.warning("Too many changes in the directory for us to sense what's new. Will try again in 30 seconds");
						oldFileSizeDB.clear();
						oldFileSizeDB.putAll(currentFileSizeDB);
						return Const.SLEEP;					
					}
					else {
						logHandler.fine("Unable to sense changes by new file. Let's try strategy 3: what file is growing in size?");
						unknownFileArray.clear();
						for (Path fil: currentFileSizeDB.keySet() )
							if (!fil.equals(latest))
								if(oldFileSizeDB.containsKey(fil))
									if(oldFileSizeDB.get(fil) < currentFileSizeDB.get(fil))
										unknownFileArray.add(fil);
						if (unknownFileArray.size() == 1) {
							logHandler.info("Found a unique new .log file growing in the directory. This must be the newest one");
							logHandler.info("New log file detected: closing '"+currentNpsLogFile.getFileName()+"'");
							in.close();
							fcNpsLogFile.close();
							latest=unknownFileArray.get(0);
							currentNpsLogFile = latest;
							fcNpsLogFile = FileChannel.open(currentNpsLogFile, StandardOpenOption.READ);
							in = new BufferedReader(Channels.newReader(fcNpsLogFile, "UTF-8"));
							logHandler.info("Opening log file '"+latest.getFileName()+"'");
							oldFileSizeDB.clear();
							oldFileSizeDB.putAll(currentFileSizeDB);
							return Const.OK;
						}	
						else {
							if (unknownFileArray.size() > 1) {
								logHandler.warning("Too many files growing in the directory for us to sense what's new. Will try again in 30 seconds");
								oldFileSizeDB.clear();
								oldFileSizeDB.putAll(currentFileSizeDB);
								return Const.SLEEP;					
							}
						}
					}
				}
			}
		}
		oldFileSizeDB.clear();
		oldFileSizeDB.putAll(currentFileSizeDB);
		logHandler.fine("Current log file keeps being the latest one");
		return Const.OK;
	}
	
	
	/**
	 * Main loop. Will keep running while {@link userid4nps#keepRunning} is set to true.
	 * Calling the class' {@link userid4nps#stop} method will set {@link userid4nps#keepRunning} to FALSE and
	 * will allow the FSM to gracefull terminate
	 * 
	 * @param trans		a valid FSM transition
	 * @throws IOException
	 */
	protected static void fsm(int trans) throws IOException {
		while ( keepRunning ) {
			try {
				if (trans == Const.INIT) {
					currentState = Const.INIT;
					init();
					trans = Const.OK;
					continue;
				}
				if ( (currentState == Const.TRYNEWFILE && trans == Const.OK) ||
						(currentState == Const.LINEPROC && trans == Const.OK) ||
						(currentState == Const.SLEEP05 && trans == Const.OK)) {
					logHandler.finest("FSM New State: TRYREADLINE");
					currentState = Const.TRYREADLINE;
					if (in.ready()) {
						xmlElement = in.readLine();
						if (xmlElement == null)
							trans = Const.NOK;
						else
							trans = Const.OK;
					}
					else
						trans = Const.NOK;
					continue;
				}
				if (currentState == Const.TRYREADLINE && trans == Const.OK) {
					logHandler.finest("FSM New State: LINEPROC");
					currentState = Const.LINEPROC;
					lineProc();
					readlineTries = 0;
					trans = Const.OK;
					continue;
				}
			} catch (IOException e1) {
				logHandler.severe("Unhandled Generic IO error");
				logHandler.severe(e1.getStackTrace()[0].toString());
				e1.printStackTrace();
				break;
			} catch (Exception e) {
				logHandler.severe("Unhandled Generic library error");
				logHandler.severe(e.getStackTrace()[0].toString());
				e.printStackTrace();
				break;
			}
			if ((currentState == Const.INIT && trans == Const.OK) ||
					(currentState == Const.SLEEP30 && trans == Const.OK) ||
					(currentState == Const.SLEEP05 && trans == Const.POLL) ) {
				logHandler.finest("FSM New State: TRYNEWFILE");
				currentState = Const.TRYNEWFILE;
				try {
					trans = tryNewFile(currentNpsLogFile);
				} catch (Exception e) {
					logHandler.severe("Error opening the NPS log directory");
					logHandler.severe(e.getStackTrace()[0].toString());
					e.printStackTrace();
					break;
				}
				continue;
			}
			try {
				if (currentState == Const.TRYNEWFILE && trans == Const.SLEEP) {
					logHandler.finest("FSM New State: SLEEP30");
					currentState = Const.SLEEP30;
					Thread.sleep(30000);
					trans = Const.OK;
					continue;
				}
				if (currentState == Const.TRYREADLINE && trans == Const.NOK) {
					logHandler.finest("FSM New State: SLEEP05, "+String.valueOf(readlineTries));
					currentState = Const.SLEEP05;
					Thread.sleep(500);
					readlineTries++;
					if (readlineTries == Const.pollNeeded) {
						readlineTries = 0;
						trans = Const.POLL;
					}
					else
						trans = Const.OK;
					continue;
				}
			} catch (InterruptedException e) {
				logHandler.severe("Unhandled generic thread error");
				logHandler.severe(e.getStackTrace()[0].toString());
				e.printStackTrace();
				break;
			}
			logHandler.severe("Reached the end of the FSM without any action");
			break;
		}
		logHandler.info("userid4nps graceful shutdown requested");
		paInterface.stopTimer();
		if (paInterface.getPanosApiC1().ready) 
			paInterface.getPanosApiC1().close();
		else
			paInterface.getPanosApiC1().giveUp=true;
		if (paInterface.getPanosApiC2().ready)
			paInterface.getPanosApiC2().close();
		else
			paInterface.getPanosApiC2().giveUp=true;
		in.close();
		fcNpsLogFile.close();
		logHandler.info("userid4nps graceful shutdown completed");
	}
}