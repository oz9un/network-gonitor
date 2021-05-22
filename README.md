
# Network Gonitor


It's a passive network monitoring application
written in Go using the GoPacket library. 

It will capture the traffic from a network interface in promiscuous mode (or read the
packets from a pcap trace file) and print a record for each packet in its
standard output, much like a simplified version of tcpdump.


## Running 

1. Run this project directly with using Go (Super user will be needed).
```bash 
sudo go run main.go
```

2. Run this project by firstly building it with Go.
```bash
go build main.go
sudo ./main
```
## Documentation & Brief Explanation

First, the packages to be used during the program's operation were determined. 

### All packages ###
Besides the gopacket packages:

- **fmt** package is used for outputs.
- **log** package is used for indicating errors.
- **encoding/hex** package is used for hex-dump of packet's payload.
- **strings** package is used for Contains function that used in filtering the payload.
- **time** package is used for determining the timeout for live capture and formatting the timestamp value.
- **os** package is used for taking system arguments.

After determining and importing all packages to be used, all of the global variables have been defined.

Since there is a difference between the global variables to be used between reading from a pcap file and live capturing, all of them were initially set as blank. "eth0" is chosen for default interface.

### Main function ###
- Take arguments that user entered from CLI.
- Define a readed_arguments_index slice for make it possible to differenciate the 'expression' part.
- Iterate over whole arguments array.
- If element is one of the following : '-s', '-r', '-i'; that means one after that argument is value of the parameter. I differenciate all parameters with that method. Thus, user could mix the order of parameters if wanted (expression parameter will be at the end of course).
- findMaxValue function is used for determining the number of arguments. Thus, we can now when 'expression' parameter starts.

### printPacketInfo function ###
- printThePacket variable is defined for determining if following packet will be printed or not.
- If there is a payload filter (-s) and following packet has that payload; then printThePacket = true.
- Otherwise, if there is a payload filter (-s) and following packet has not that payload; then printThePacket =false.
- And the last option is that the -s parameter is not given by user. In that situation printThePacket is also true.
- After printing out timestamp with correct format, MAC adresses, package type, length of packet; Ip layer is started.
- In Ip layer, Ip addresses printed out.
- On line 141-142 I checked if packet has UDP/TCP layer! I think that is important for error-handling.
- After controls, I created an array of TCP FLAGS on line 155 and array of boolean values of them on line 156.
- Thus, I can iterate over them and mark them if the flag was used.
- For example, if 3rd element of all_flags_value array is True, then 3rd element of all_flags is used on packet. We can easily get the name of the flag with: all_flags[2].
- Both UDP/TCP packets, port numbers&protocol are printed out. (+FLAGS in TCP case).
- While printing protocol names, protocol numbers are considered. On line 172 (ip.Protocol == 1) controls if the packet is ICMP or not.
- Finally, I reached the application layer and all I need to print out is payload!
- I used hex.Dump function for that purpose.
## Usage/Examples

Example usages of program:
```bash
	sudo go run program.go -i ens33 -s "youtube"
	sudo go run program.go ../Desktop/SkypeIRC.cap -s "Content-Length: 7"
	sudo go run program.go -r ../Desktop/SkypeIRC.cap -s skype
	sudo go run program.go -r ../Desktop/ipv4frags.pcap -s abc "icmp and len >= 1000"
	sudo go run program.go -r ../Desktop/ipv4frags.pcap -s abc "icmp and len >= 466"
	sudo go run program.go -i ens33
	sudo go run program.go -i ens33 tcp and port 80
	sudo go run program.go -i ens33 "tcp and len >= 180"
```
**As you see, you can specify parameters with quotation marks (""). But if there is not any special characters like ">", "<", the quotation marks are not necessary.**

  
## Output format
Network Gonitor started with the following command:
```bash
sudo go run main.go -i ens33 "tcp and port 80"
````
![App Screenshot](https://i.ibb.co/FYsPYvz/Screenshot-406.png)

 