import nmap

# Create an instance of the PortScanner class from the nmap module
scanner = nmap.PortScanner()

# Display a welcome message
print("Welcome, this is a simple nmap automation tool")
print("<------------------------------------------>")

# Prompt the user to enter an IP address to scan
ip_addr = input("Please enter the IP address you want to scan: ")
print("The IP you entered is:", ip_addr)
type(ip_addr)

# Prompt the user to select a type of scan
resp = input(""" \nPlease enter the type of scan you want to run
	1) SYN ACK Scan
	2) UDP Scan
	3) Comprehensive Scan
	""")
print("You have selected option: ", resp)

# Perform the selected scan based on user input
if resp == '1':
	# Perform a SYN ACK scan
	print("Nmap Version: ", scanner.nmap_version())
	scanner.scan(ip_addr, '1-1024', '-v -sS')
	print(scanner.scaninfo())
	print("IP Status: ", scanner[ip_addr].state())
	print(scanner[ip_addr].all_protocols())
	print("Open Ports: ", scanner[ip_addr]['tcp'].keys())
elif resp == '2':
	# Perform a UDP scan
	print("Nmap Version: ", scanner.nmap_version())
	scanner.scan(ip_addr, '1-1024', '-v -sU')
	print(scanner.scaninfo())
	print("IP Status: ", scanner[ip_addr].state())
	print(scanner[ip_addr].all_protocols())
	print("Open Ports: ", scanner[ip_addr]['udp'].keys())
elif resp == '3':
	# Perform a comprehensive scan
	print("Nmap Version: ", scanner.nmap_version())
	scanner.scan(ip_addr, '1-1024', '-v -sS -sV -sC -A -O')
	print(scanner.scaninfo())
	print("IP Status: ", scanner[ip_addr].state())
	print(scanner[ip_addr].all_protocols())
	print("Open Ports: ", scanner[ip_addr]['tcp'].keys())
elif >= '4':
	# Invalid option selected
	print("Please enter a valid option")