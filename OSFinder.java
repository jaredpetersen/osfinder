import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;

/**
 * Rogue Computer Finder
 * This program uses Nmap and the windows command line to find all of the Windows computers
 * that are one the same subnet as the user (support for Windows XP and Windows 7).
 * 
 * @author Jared Petersen
 * @version 3.0 01/06/2015
 * 
 * @param commands Nmap commands that are passed in by the main method
 */
public class OSFinder {
	
	// ProcessBuilder is used to actually build and run applications (ipconfig and Nmap)
	ProcessBuilder pb = new ProcessBuilder();
	
	// Used to read the output from processes
	InputStream inputStream;
    InputStreamReader inputStreamReader;
    BufferedReader bufferedReader;
    
    // Indicates whether the program will output extra stuff
    static boolean extraOutput = false;
    
    // Operating System that is being searched for
    static String searchOS = "Windows XP";
	
	/**
	 * The main method. Creates an instance of this class that it then uses to find the subnet
	 * for later use in the Nmap OS detection command.
	 * 
	 * @param args An array of strings
	 */
	public static void main(String[] args) {		
		
		// Loop over the arguments
		for (String arg : args)
		{
			
			// Check if the user wants extra output
			if (arg.equals("-eo"))
			{
				extraOutput = true;
			}
			
			// Check if the user wants to look for Windows 7 computers instead
			else if (arg.equals("-os7"))
			{
				searchOS = "Windows 7";
			}
			
			// Argument not found
			else
			{
				// Print error message and shutdown the program
				printInvalidArgument();
				System.exit(1);
			}
			
		}
		
		// Print starting message
		printWelcome();
		
		// Create an instance of the class
		OSFinder OSFinder = new OSFinder();
		
		// Find the subnet and let the user know
		String subnet = OSFinder.getSubnet();
		printFoundSubnet(subnet);
		// Determine the name of the CSV output file
		String fileName = "osfinder" + subnet + ".csv";
		
		// Use the previously determined subnet to run an Nmap command to find all of the OSs
		// Nmap command should look something like nmap -p 445 --script smb-os-discovery 140.211.114.0/24
		String finalCommand = subnet + "/24";
		String[] commands = {"cmd.exe", "/c", "nmap ", "-p", "445", "--script", "smb-os-discovery", finalCommand};
		OSFinder.executeNmapCommand(commands, fileName);
		
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
				    	subnet = line.substring(39);
				    	
				    	// Get only the first three sections of the subnet
				    	// Replace the last section with a 0 so that the whole subnet can be scanned
				    	subnet = subnet.substring(0, subnet.indexOf('.', subnet.indexOf('.', subnet.indexOf('.') + 1) + 1) + 1) + '0';
				    	
				    	// Get out of the loop, we found what we needed
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
	 * format and outputs the desired data to a CSV file. Also outputs the data to the terminal if user
	 * elects to do so at startup.
	 * 
	 * @param commands Nmap commands that are passed in by the main method
	 */
	private void executeNmapCommand(String[] commands, String fileName)
	{
		String macAddress = null;
		String hardware = null;
		String operatingSystem = null;
		String computerName = null;
		int osFound = 0;
		
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
				
				// See if the scan found a new computer
				if (line.startsWith("Nmap scan report for"))
				{
					// Scan found a new computer, output the previous data
					
					// Make sure that the previous data is all there and is what we're looking for
					if (checkDataValid(macAddress, operatingSystem, computerName))
					{
						
						// Didn't test for hardware earlier because that's more of an added bonus
		    			// Testing now so that we can remove the parenthesis that is part of the data
		    			if (hardware != null)
			    		{
			    			// Remove parenthesis before outputting hardware string
					    	hardware = hardware.replace("(", "").replace(")", "");
			    		}
		    			
		    			else
		    			{
		    				// String was null, just make it an empty string
		    				hardware = "";
		    			}
		    			
		    			// Write the data to the CSV file
				    	bufferedWriter.write(operatingSystem + ", " + computerName + ", " + hardware + ", " + macAddress);
				    	bufferedWriter.newLine();
				    	
				    	// Increment the Windows XP computers found counter
				    	osFound++;
				    	
				    	// Check if the user wants the output to be displayed in the terminal
				    	if (extraOutput)
				    	{
				    		// Print out the variables in the terminal
				    		System.out.println(macAddress + " " + hardware + " " + operatingSystem + " " + computerName);
				    	}
				    }
					
					// Else -- Do nothing
					
					// Set variables back to null
					macAddress = null;
					operatingSystem = null;
			    	computerName = null;
			    	hardware = null;
				}
				
				// Get the MAC Address
				else if (line.startsWith("MAC Address: "))
			    {
					// Assign necessary data to strings for later processing
					macAddress = line.substring(13, 30);
					hardware = line.substring(31);
			    }
		    	
		    	// Get the Operating System
		    	else if (line.startsWith("|   OS: "))
			    {
		    		// Assign OS data to a string for later processing
		    		operatingSystem = line.substring(8);
			    }
		    	
		    	// Get the Computer Name
		    	else if (line.startsWith("|   Computer name: "))
			    {
		    		// Assign computer name data to a string for later processing
		    		computerName = line.substring(19);
			    }
		    	
		    	// Else -- Do nothing
		    	
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
	            	// Print a sucess message and the number of <INSERT OS HERE> computers found
	            	printSuccess(osFound);
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
	
	private boolean checkDataValid(String macAddress, String operatingSystem, String computerName)
	{
		// See if all of the information is there
    	if (macAddress != null && operatingSystem != null && computerName != null)
	    {
	    	// Check if the computer has the desired OS
    		if (operatingSystem.startsWith(searchOS))
			{
		    	// Found the OS we're looking for    			
    			return true;
			}
    		
    		else
    		{
    			// OS is not desired
    			return false;
    		}
	    }
    	
    	else
    	{
    		// Not enough data
    		return false;
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
		System.out.println("\nStarting OSFinder. Please Wait...\n");
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
		System.out.println("Subnet is " + subnet + "\n");
	}
	
	/**
	 * Prints a notification that the Nmap OS scan has begun
	 */
	private void printNmapStatus()
	{
		System.out.println("Executing Nmap OS Scan...");
	}
	
	/**
	 * Prints the number of computers found by the application with the OS we're looking for
	 * 
	 * @param xpFound The number of computers with the desired OS that have been found
	 */
	private void printSuccess(int osFound)
	{
		String pluralOrSingular;
		
		if (osFound == 1)
		{
			pluralOrSingular = " computer was found.";
		}
		else
		{
			pluralOrSingular = " computers were found.";
		}
		
		System.out.println(osFound + " " + searchOS + pluralOrSingular);

		
	}
	
	/**
	 * Prints a notification that the Nmap command used may have failed
	 */
	private void printNmapProcessError()
	{
		System.out.println("Nmap command may have failed. Consider restarting OSFinder.");
	}
	
	/**
	 * Prints a quit message to signal the end of the application
	 * 
	 * @param fileName The name of the CSV file that was created
	 */
	private static void printQuit(String fileName)
	{
		System.out.println("\nData was saved to " + fileName + "\nQuitting OSFinder.");
	}
	
	/**
	 * Prints an invalid argument error message to the end user
	 */
	private static void printInvalidArgument()
	{
		System.out.println("Invalid argument:\nPlease see the manual at https://github.com/jaredpetersen/OSFinder");
	}
}
