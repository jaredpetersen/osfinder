OSFinder
===============

OSFinder uses Nmap to find the operating system, computer name, hardware, and the MAC Address of computers on a subnet. This data is outputted in the form of a CSV that is generated in the same directory that OSFinder is run in. **Users must be connected to the subnet via ethernet for the program to work.** OSFinder currently only looks for either **Windows XP** or **Windows 7** computers, though it could be expanded out to include other operating systems.

Instructions
===============
1. Install Nmap for Windows (http://nmap.org/download.html#windows)
2. Download the OSFinder Java file and turn it into a JAR **OR** just download the JAR file directly from http://www.wou.edu/~jpetersen11/code/osfinder/OSFinder-v3.01.jar (older versions can be found at http://www.wou.edu/~jpetersen11/code/osfinder).
3. Connect to the desired subnet **via ethernet** and run the JAR file (`java -jar OSFinder-v3.01.jar` in the same directory as the file). Arguments can be used as well (e.g., `java -jar OSFinder-v3.01.jar -eo -os7`).

How it Works
===============
The program first finds the computer's subnet from running a command on the windows command line (`ipconfig | findstr [0-9]`), which returns the computer's local ethernet gateway along with some other information. The program then uses the subnet in an Nmap command (`nmap -p 445 --script smb-os-discovery ###.###.###.0/24`), which is also run from the windows command line. OSFinder then parses the results of the Nmap command and only returns the operating system, computer name, hardware (based on the MAC Address), and the MAC Address.

Arguments
===============
| Argument | Explanation                                                                   |
| -------- | ----------------------------------------------------------------------------- |
| `-eo`    | Outputs the data written into the CSV file into the terminal window as well   |
| `-os7`   | Looks for **Windows 7** computers only, instead of the default **Windows XP** |
