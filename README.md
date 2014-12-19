WindowsXPFinder
===============

Uses Nmap to find all Windows XP computers on the subnet

Instructions
===============
1. Install Nmap for Windows (http://nmap.org/download.html#windows)
2. Download the Java file and turn it into a JAR (http://docs.oracle.com/javase/tutorial/deployment/jar/build.html)
3. Connect to the subnet that you would like to find Windows XP computers on via ethernet and run the JAR file (http://stackoverflow.com/questions/8511063/how-to-run-jar-file-by-double-click-on-windows-7-64)

How it Works
===============
The program first finds the computer's subnet from running a command on the windows command line (```ipconfig | findstr [0-9]```), which returns the computer's local ethernet gateway along with some other information. The program then uses the subnet in an Nmap command (```nmap -p 445 --script smb-os-discovery ###.###.###.0/24```) that is also called from the windows command line. As of right now, WindowsXPFinder will just print the output of the Nmap command. Later on, actual filtering will be performed so that only Windows XP computers will be printed out.

TO DO
===============

- Add filtering to the Nmap output (Issue #1)
