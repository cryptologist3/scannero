import nmap
import sys

# Prompt user to input IP address to scan
ip_address = input("Enter the IP address to scan: ")

# Initialize the Nmap scanner
nm_scan = nmap.PortScanner()

# Print available options
print("\nOptions:")
print("1. SYN ACK scan")
print("2. UDP scan")
print("3. Comprehensive scan")
print("4. Quick scan")
print("5. Intense scan")

# Prompt user to select an option
option = input("Enter the number of the scan type you want to perform: ")

# Perform the selected scan
if option == "1":
    print("\nPerforming SYN ACK scan for IP address " + ip_address)
    nm_scan.scan(ip_address, '1-1024', '-v -sS')
elif option == "2":
    print("\nPerforming UDP scan for IP address " + ip_address)
    nm_scan.scan(ip_address, '1-1024', '-v -sU')
elif option == "3":
    print("\nPerforming comprehensive scan for IP address " + ip_address)
    nm_scan.scan(ip_address, '1-1024', '-v -sS -sV -sC -A -O')
elif option == "4":
    print("\nPerforming quick scan for IP address " + ip_address)
    nm_scan.scan(ip_address, '1-1024', '-v -T4')
elif option == "5":
    print("\nPerforming intense scan for IP address " + ip_address)
    nm_scan.scan(ip_address, '1-1024', '-v -T4 -A -v')
else:
    print("Invalid option selected")
    sys.exit(0)

# Print the results of the scan
print("\nScan results:")
for host in nm_scan.all_hosts():
    print("Host : %s (%s)" % (host, nm_scan[host].hostname()))
    print("State : %s" % nm_scan[host].state())
    for protocol in nm_scan[host].all_protocols():
        print("\nProtocol : %s" % protocol)
        
        # Print all open ports
        lport = nm_scan[host][protocol].keys()
        lport = sorted(lport)
        for port in lport:
            print("port : %s\tstate : %s" % (port, nm_scan[host][protocol][port]['state']))
