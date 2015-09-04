package uid4nps;

import java.io.IOException;
import java.io.StringReader;
import java.util.HashMap;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;

import org.xml.sax.Attributes;
import org.xml.sax.ContentHandler;
import org.xml.sax.InputSource;
import org.xml.sax.Locator;
import org.xml.sax.SAXException;
import org.xml.sax.XMLReader;

/**
 * Use the {@link UseridNpsDtsParser#IMIParser} method for each NPS DTS-formated element (Radius Log entries)
 * {@link UseridNpsDtsParser#IMIParser} will return TRUE is the element in compliant (Acc-Start with UserName and FramedIP)
 * Element values available after parsing accessing the {@link UseridNpsDtsParser#elementData} field with keys "User-Name", "Framed-IP-Address" and "NAS-Identifier"
 *
 */
public class UseridNpsDtsParser {

	/**
	 * Will host all node names and values from the DTS Compliant entry
	 */
	public HashMap<String, String> elementData;
	/**
	 * Stores the Accounting type ("1"=start / "2"=stop) of this entry provided it is valid
	 */
	public String AcctStatusType;
	/**
	 * Stores the username of this entry provided it is valid
	 */
	public String UserName;
	/**
	 * Stores the IP-Address of this entry provided it is valid
	 */
	public String FramedIPAddress;
	/**
	 * Stores the NAS Identifier of this entry provided it is valid
	 */
	public String NASIdentifier;
	private XMLReader xmlReader;
	private InputSource is;
	/**
	 */
	protected String defaultDomain;
	private Logger logHandler;
	private int mindex;
	private Pattern includePat;
	private Matcher includeMatch;

	
	/**
	 * Initializes the SAX Content Handler and other class fields
	 * 
	 * @param defaultDomain		The default Domain Name to be used for Accounting entries without an explicit domain
	 * @throws ParserConfigurationException
	 * @throws IOException
	 * @throws InterruptedException
	 * @throws SAXException
	 */
	public UseridNpsDtsParser(String defaultDomain, String includePattern) throws ParserConfigurationException, IOException, InterruptedException, SAXException
	{
		logHandler = Logger.getLogger("userid4nps");
		elementData = new HashMap<String, String>();
		this.defaultDomain = defaultDomain;
		includePat = Pattern.compile(includePattern);
		is = new InputSource();
		SAXParserFactory spf = SAXParserFactory.newInstance();
		SAXParser saxParser = spf.newSAXParser();
		xmlReader = saxParser.getXMLReader();
		xmlReader.setContentHandler(new ContentHandler() {
			
			private String currentKey;
			
			@Override
			public void startPrefixMapping(String prefix, String uri)
					throws SAXException {
			}
			
			@Override
			public void startElement(String uri, String localName, String qName,
					Attributes atts) throws SAXException {
				currentKey=qName;
			}
			
			@Override
			public void startDocument() throws SAXException {
				elementData.clear();
			}
			
			@Override
			public void skippedEntity(String name) throws SAXException {
			}
			
			@Override
			public void setDocumentLocator(Locator locator) {
			}
			
			@Override
			public void processingInstruction(String target, String data)
					throws SAXException {
			}
			
			@Override
			public void endPrefixMapping(String prefix) throws SAXException {
			}
			
			@Override
			public void endElement(String uri, String localName, String qName)
					throws SAXException {
			}
			
			@Override
			public void endDocument() throws SAXException {
			}
			
			@Override
			public void characters(char[] ch, int start, int length)
					throws SAXException {
				String value = "";
				for (int b=0;b<length;b++)
					value+=ch[b+start];
				elementData.put(currentKey, value);
			}

			@Override
			public void ignorableWhitespace(char[] ch, int start, int length)
					throws SAXException {
			}
		});
	}

	/**
	 * This method will discard any non useful DTS message. We'll only keep these one that satisfy:
	 * <ul>
	 * <li>Have an "Acct-Status-Type" element node
	 * <li>The "Acct-Status-Type" element node has values "1" (start) or "2" (stop) or "3" (interim)
	 * <li>Have an "User-Name" element node
	 * <li>Have a "Framed-IP-Address"element node
	 * </ul>
	 * In case the "User-Name" value doesn't include a domain name we'll use the one at {@link UseridNpsDtsParser#defaultDomain}
	 * 
	 * @param element	The DTS Compliant NPS log formated entry to be parsed
	 * @return		TRUE if we've been able to parse the entry so caller knows there is valid data available at {@link UseridNpsDtsParser#elementData}
	 * @throws IOException
	 */
	public Boolean IMIParser (String element) throws IOException {
		AcctStatusType = null;
		UserName = null;
		FramedIPAddress = null;
		includeMatch = includePat.matcher(element);
		if (includeMatch.matches()) {
			logHandler.fine("Provided NPS log element matches the include pattern");
			is.setCharacterStream(new StringReader(element));
			try {
				xmlReader.parse(is);
				is.getCharacterStream().close();
			} catch (SAXException e) {
				logHandler.warning("Error parsing document");
			}
			if (elementData.get("Acct-Status-Type") != null) { // It is a Radius Accounting Record
				AcctStatusType = elementData.get("Acct-Status-Type");
				if(AcctStatusType.equals("3") || AcctStatusType.equals("1") || AcctStatusType.equals("2")) // It is a "Start", "Stop" or "Interim" type of Accounting Record
					if (elementData.get("User-Name") != null ) { // There is a username attribute
						String UserNameString = elementData.get("User-Name").toLowerCase();
						if (!UserNameString.startsWith("host/"))  // IMI: It is not a host based authentication
							if(elementData.get("Framed-IP-Address") != null) { // There is an IP address
								FramedIPAddress = elementData.get("Framed-IP-Address");
								if (UserNameString.matches(".*@.*")) { // It is a username@domain style
									mindex = UserNameString.indexOf("@");
									UserName = UserNameString.substring(mindex+1,UserNameString.length())+"\\"+UserNameString.substring(0, mindex);
								}
								else if(UserNameString.matches(".*\\\\.*")) 
									UserName = UserNameString;
								else 
									UserName = defaultDomain+"\\"+UserNameString;
								logHandler.fine("Received a valid userID NPS log element ("+AcctStatusType+";"+UserName+";"+FramedIPAddress+")");
								NASIdentifier = elementData.get("NAS-Identifier");
								return true;
							}
					}
			}
		}
		return false;
	}
}
