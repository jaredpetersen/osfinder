import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;

/**
 * Windows XP Finder
 * This program uses Nmap and the windows command line to find all of the Windows XP computers
 * that are one the same subnet as the user.
 * 
 * @author Jared Petersen
 * @version 2.0 12/19/2014
 * 
 * @param commands Nmap commands that are passed in by the main method
 */
public class WindowsXPFinder {
	
	// ProcessBuilder is used to actually build and run applications (ipconfig and Nmap)
	ProcessBuilder pb = new ProcessBuilder();
	
	// Used to read the output from processes
	InputStream inputStream;
    InputStreamReader inputStreamReader;
    BufferedReader bufferedReader;
	
	/**
	 * The main method. Creates an instance of this class that it then uses to find the subnet
	 * for later use in the Nmap OS detection command.
	 * 
	 * @param args An array of strings
	 */
	public static void main(String[] args) {		
		
		// Print starting message
		printWelcome();
		
		// Create an instance of the class
		WindowsXPFinder windowsXPFinder = new WindowsXPFinder();
		
		// Find the subnet and let the user know
		String subnet = windowsXPFinder.getSubnet() + "0";
		printFoundSubnet(subnet);
		// Determine the name of the CSV output file
		String fileName = "windowsxpfinder" + subnet + ".csv";
		
		// Use the previously determined subnet to run an Nmap command to find all of the OSs
		// Nmap command should look something like nmap -p 445 --script smb-os-discovery 140.211.114.0/24
		String finalCommand = subnet + "/24";
		String[] commands = {"cmd.exe", "/c", "nmap ", "-p", "445", "--script", "smb-os-discovery", finalCommand};
		windowsXPFinder.executeNmapCommand(commands, fileName);
		
		// Print the closing message
		printQuit(fileName);
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
		
		printSubnetStatus();
		
		try 
		{
			// Give the ProcessBuilder the ipconfig commands
			pb.command("cmd.exe", "/c", "ipconfig | findstr [0-9].\\.");
			// Start the process
			Process subnetProcess = pb.start();
			
			// Get the data from the process being run
			inputStream = subnetProcess.getInputStream();
	        inputStreamReader = new InputStreamReader(inputStream);
	        bufferedReader = new BufferedReader(inputStreamReader);
	        String line;
	        
	        // Begin looping over the data, adding new data lines to the line string
	        // Cut out of the loop when the bufferedReader is out of data
			while ((line = bufferedReader.readLine()) != null)
			{
				// Make sure that the line being read in is large enough to be looked at by substring()
				if (line.length() >= 39)
				{
					// Check to see if the line is the default gateway
				    if (line.startsWith("   Default Gateway . . . . . . . . . : "))
				    {
				    	// Get the subnet
				    	subnet = line.substring(39, 50);
				    	break;
				    }
				}
			}
			
			// Wait for the subnet process to finish
			// Need to have this try/catch statement inside the IOException try/catch
	        try {
	            subnetProcess.waitFor();
	        } catch (InterruptedException e) {
	        	// In the case that the process is interrupted, print the error
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
	private void executeNmapCommand(String[] commands, String fileName)
	{
		String macAddress = null;
		String hardware = null;
		String operatingSystem = null;
		String computerName = null;
		int xpFound = 0;
		
		printNmapStatus();
		
		try 
		{
			// Give ProcessBuilder the Nmap commands
			pb.command(commands);
			pb.redirectErrorStream(true);
			// Start the process
			Process nmapProcess = pb.start();
			
			// Get the data from the process being run
			inputStream = nmapProcess.getInputStream();
			inputStreamReader = new InputStreamReader(inputStream);
			bufferedReader = new BufferedReader(inputStreamReader);
			String line;
			
	    	// Prepare to write the CSV file
	    	File file = new File(fileName);
	    	FileWriter fileWriter = new FileWriter(file);
	    	BufferedWriter bufferedWriter = new BufferedWriter(fileWriter);
			
			// Add the CSV File Headings
			bufferedWriter.write("Operating System, Computer Name, Hardware, MAC Address");
			bufferedWriter.newLine();
	        
	        // Begin looping over the data, adding new data lines to the line string
	        // Cut out of the loop when the bufferedReader is out of data
			while ((line = bufferedReader.readLine()) != null)
			{
				// Get the MAC Address
		    	if (line.startsWith("MAC Address: "))
			    {
					macAddress = line.substring(13, 30);
					hardware = line.substring(31);
			    }
		    	
		    	// Get the Operating System
		    	else if (line.startsWith("|   OS: "))
			    {
					operatingSystem = line.substring(8);
			    }
		    	
		    	// Get the Computer Name
		    	else if (line.startsWith("|   Computer name: "))
			    {
					computerName = line.substring(19);
			    }
		    	
		    	// Else -- Do nothing
			    
		    	// See if all of the information is there
		    	if (macAddress != null && operatingSystem != null && computerName != null)
			    {
			    	// Check if the computer is Windows XP
		    		if (operatingSystem.startsWith("Windows 7"))
	    			{
				    	// Didn't test for hardware earlier because that's more of an added bonus
		    			// Testing now so that we can remove the parenthesis that were part of the data
		    			if (hardware != null)
			    		{
			    			// Remove Parenthesis before outputting hardware string
					    	hardware = hardware.replace("(", "").replace(")", "");
			    		}
		    			else
		    			{
		    				hardware = "";
		    			}
				    	
				    	// Write the data to the CSV file
				    	bufferedWriter.write(operatingSystem + ", " + computerName + ", " + hardware + ", " + macAddress);
				    	bufferedWriter.newLine();
				    	
				    	// Increment the Windows XP computers found counter
				    	xpFound++;
	    			}
			    }
		    	
		    	// Set variables back to null, next computer
		    	operatingSystem = null;
		    	computerName = null;
		    	hardware = null;
		    	macAddress = null;
		    	//System.out.println(line);
		    	
			}
			
			// Shut the file writer down
			bufferedWriter.close();
			
			// Wait for the Nmap process to finish
			// Need to have this try/catch statement inside the IOException try/catch
	        try
	        {
	            // exitValue is an indicator of the success of the process
	        	int exitValue = nmapProcess.waitFor();
	            
	        	// An exitValue of 0 is complete success
	            if (exitValue == 0)
	            {
	            	// Print a sucess message and the number of Windows XP computers found
	            	printSuccess(xpFound);
	            }
	            // Anything else can indicate a problem with either ProcessBuilder or the command being run
	            else
	            {
	            	// Just tell users to try again
	            	printNmapProcessError();
	            }
	            
	        }
	        catch (InterruptedException e)
	        {
	            // In the case that the process is interrupted, print the error
	        	e.printStackTrace();
	        }
	        
		}
		// Used for the buffered reader and input stream bits
		catch (IOException e)
		{
			e.printStackTrace();
		}
        
	}
	
	// -------------------------------------------------------------------------------------------------
	// ------------------------------ Methods used to print notifications ------------------------------
	// -------------------------------------------------------------------------------------------------
	
	/**
	 * Prints a welcome message to signal the start of the application
	 */
	private static void printWelcome()
	{
		System.out.println("Starting Windows XP Finder. Please Wait...\n");
	}
	
	/**
	 * Prints a notification that the application is finding the subnet
	 */
	private void printSubnetStatus()
	{
		System.out.println("Finding Subnet...");
	}
	
	/**
	 * Prints the subnet
	 */
	private static void printFoundSubnet(String subnet)
	{
		System.out.println("Subnet is " + subnet);
	}
	
	/**
	 * Prints a notification that the Nmap OS scan has begun
	 */
	private void printNmapStatus()
	{
		System.out.println("Executing Nmap OS Scan...");
	}
	
	/**
	 * Prints the number of Windows XP machines found by the application
	 * 
	 * @param xpFound The number of Windows XP Computers found
	 */
	private void printSuccess(int xpFound)
	{
		System.out.println(xpFound + " Windows XP Computers were found.");
	}
	
	/**
	 * Prints a notification that the Nmap command used may have failed
	 */
	private void printNmapProcessError()
	{
		System.out.println("Nmap command may have failed. Consider restarting Windows XP Finder.");
	}
	
	/**
	 * Prints a quit message to signal the end of the application
	 * 
	 * @param fileName The name of the CSV file that was created
	 */
	private static void printQuit(String fileName)
	{
		System.out.println("\nData was saved to " + fileName + "\nQuitting Windows XP Finder.");
	}
}
