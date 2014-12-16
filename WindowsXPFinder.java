import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;

/**
 * Windows XP Finder
 * This program uses Nmap and the windows command line to find all of the Windows XP computers
 * that are one the same subnet as the user.
 * 
 * @author Jared Petersen
 * @version 1.0 12/15/2014
 * 
 * @param commands Nmap commands that are passed in by the main method
 */
public class WindowsXPFinder {
	
	// ProcessBuilder is used to actually build and run applications (ipconfig and Nmap)
	ProcessBuilder pb = new ProcessBuilder();
	
	/**
	 * The main method. Creates an instance of this class that it then uses to find the subnet
	 * for later use in the Nmap OS detection command.
	 * 
	 * @param args An array of strings
	 */
	public static void main(String[] args) {		
		
		// Create an instance of the class
		WindowsXPFinder windowsXPFinder = new WindowsXPFinder();
		
		// Find the subnet
		String subnet = windowsXPFinder.getSubnet();
		
		// Use the previously determined subnet to run an Nmap command to find all of the OSs
		// Nmap command should look something like nmap -p 445 --script smb-os-discovery 140.211.114.0/24
		String finalCommand = "--script smb-os-discovery " + subnet + "0/24";
		String[] commands = {"cmd.exe", "/c", "nmap ", "-p 445", finalCommand};
		windowsXPFinder.executeNmapCommand(commands);

	}
	
	/**
	 * Returns the subnet that the user is currently connected to (via ethernet) as a string.
	 * This is used because Nmap OS detection does not work very well across subnets because
	 * of routers and switches.
	 * 
	 * @return subnet An ethernet gateway string obtained from the "ipconfig" command
	 */
	private String getSubnet()
	{
		String subnet = "";
		
		try 
		{
			// Give the ProcessBuilder the ipconfig commands
			pb.command("cmd.exe", "/c", "ipconfig | findstr [0-9].\\.");
			// Start the process
			Process subnetProcess = pb.start();
			
			// Get the data from the process being run
			InputStream inputStream = subnetProcess.getInputStream();
	        InputStreamReader inputStreamReader = new InputStreamReader(inputStream);
	        BufferedReader bufferedReader = new BufferedReader(inputStreamReader);
	        String line;
	        
	        // Begin looping over the data, adding new data lines to the line string
	        // Cut out of the loop when the bufferedReader is out of data
			while ((line = bufferedReader.readLine()) != null)
			{
				// Make sure that the line being read in is large enough to be looked at by substring()
				if (line.length() >= 39)
				{
					// Check to see if the line is the default gateway
				    if (line.substring(0, 39).equals("   Default Gateway . . . . . . . . . : "))
				    {
				    	// Get the subnet
				    	subnet = line.substring(39, 51);
				    	break;
				    }
				}
			}
			
			// Wait for the subnet process to finish
			// Need to have this try/catch statement inside the IOException try/catch
	        try {
	            subnetProcess.waitFor();
	        } catch (InterruptedException e) {
	            e.printStackTrace();
	        }
	        
		}
		// Used for the buffered reader and input stream bits
		catch (IOException e)
		{
			e.printStackTrace();
		}
		
		return subnet;
	}
	
	/**
	 * Executes the Nmap OS detection command passed into it (see main method) in ProcessBuilder
	 * format and prints the output into the console. Will later do some filtering to only 
	 * return Windows XP computers.
	 * 
	 * @param commands Nmap commands that are passed in by the main method
	 */
	private void executeNmapCommand(String[] commands)
	{
		try 
		{
			// Give ProcessBuilder the Nmap commands
			pb.command(commands);
			// Start the process
			Process nmapProcess = pb.start();
			
			// Get the data from the process being run
			InputStream is = nmapProcess.getInputStream();
	        InputStreamReader isr = new InputStreamReader(is);
	        BufferedReader br = new BufferedReader(isr);
	        String line;
	        
	        // Begin looping over the data, adding new data lines to the line string
	        // Cut out of the loop when the bufferedReader is out of data
			while ((line = br.readLine()) != null)
			{
			    System.out.println(line);
			}
			
			// Wait for the Nmap process to finish
			// Need to have this try/catch statement inside the IOException try/catch
	        try
	        {
	            // exitValue is an indicator of the success of the process
	        	int exitValue = nmapProcess.waitFor();
	            
	        	// An exitValue of 0 is complete success
	            if (exitValue == 0)
	            {
	            	System.out.println("\n\nProgram ran sucessfully. Quitting Windows XP Finder.");
	            }
	            // Anything else can indicate a problem with either ProcessBuilder or the command being run
	            // Just tell users to try again
	            else
	            {
	            	System.out.println("\n\nNmap command may have failed. Quitting Windows XP Finder.");
	            }
	            
	        }
	        catch (InterruptedException e)
	        {
	            e.printStackTrace();
	        }
	        
		}
		// Used for the buffered reader and input stream bits
		catch (IOException e)
		{
			e.printStackTrace();
		}
        
	}
}
