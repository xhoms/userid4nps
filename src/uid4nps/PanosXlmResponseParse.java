package uid4nps;

import java.io.IOException;
import java.io.StringReader;
import java.util.logging.Logger;

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
 * Basic class to deal with PANOS response XML message received by a user-id API call
 *
 */
public class PanosXlmResponseParse {

	private XMLReader xmlReader;
	private Logger logHandler;
	private InputSource is;
	/**
	 * FALSE means we've received a response error message from our user-id API call
	 * TRUE otherwise
	 */
	protected Boolean succes;


	/**
	 * Instantiates the class fields and builds the SAX ContentHandler
	 * 
	 * @throws ParserConfigurationException
	 * @throws SAXException
	 */
	public PanosXlmResponseParse() throws ParserConfigurationException, SAXException {
		logHandler = Logger.getLogger("userid4nps");
		is = new InputSource();
		SAXParserFactory spf = SAXParserFactory.newInstance();
		SAXParser saxParser = spf.newSAXParser();
		xmlReader = saxParser.getXMLReader();
		xmlReader.setContentHandler(new ContentHandler() {

			@Override
			public void setDocumentLocator(Locator locator) {
			}

			@Override
			public void startDocument() throws SAXException {
			}

			@Override
			public void endDocument() throws SAXException {
			}

			@Override
			public void startPrefixMapping(String prefix, String uri)
					throws SAXException {
			}

			@Override
			public void endPrefixMapping(String prefix) throws SAXException {
			}

			@Override
			public void startElement(String uri, String localName,
					String qName, Attributes atts) throws SAXException {
				if(qName.equals("response"))
					if (atts.getValue("status").equals("error"))
						succes=false;
			}

			@Override
			public void endElement(String uri, String localName, String qName)
					throws SAXException {
			}

			@Override
			public void characters(char[] ch, int start, int length)
					throws SAXException {
			}

			@Override
			public void ignorableWhitespace(char[] ch, int start, int length)
					throws SAXException {
			}

			@Override
			public void processingInstruction(String target, String data)
					throws SAXException {
			}

			@Override
			public void skippedEntity(String name) throws SAXException {
			} });
	}
	
	/**
	 * Tries to parse the XML response message received from the PANOS device after a user-id API call
	 * 
	 * @param response		The XML response message received from the PANOS device after we sent the user-id API message
	 * @return				FALSE if the response includes an error result message. TRUE otherwise
	 * @throws IOException
	 */
	public Boolean panosResponseParse(String response) throws IOException {
		succes = true;
		is.setCharacterStream(new StringReader(response));
		try {
			xmlReader.parse(is);
			is.getCharacterStream().close();
		} catch (SAXException e) {
			logHandler.warning("Error parsing PANOS response");
		}
		return succes;
	}
}
