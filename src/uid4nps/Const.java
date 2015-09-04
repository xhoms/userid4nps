package uid4nps;

/**
 * Convenience interface to host application constants
 *
 */
public interface Const {
	/**
	 * 
	 */
	public final int INIT = 0;
	public final int CALCMONTH = 10;	
	public final int TRYREADLINE = 30;	
	public final int LINEPROC = 40;	
	public final int SLEEP05 = 50;	
	public final int SLEEP10 = 60;	
	public final int SLEEP30 = 70;	
	public final int TRYNEWFILE = 80;
	
	public final int OK = -10;	
	public final int NOK = -20;	
	public final int MONTHCHANGE = -30;
	public final int POLL = -40;
	public final int SLEEP = -50;
	
	public final int pollNeeded = 10;
	
	public final String cmdLineError = "usage: userid4nps -config=<config_file>\n";
}
