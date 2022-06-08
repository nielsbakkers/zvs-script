#!/bin/bash
#
# Version	| 1.0
#
#################################################################
#								#
#		Zeek Vulnerabilitie Scanner			#
#								#
#################################################################
#
#
#
#################################################################
#								#
#			Color Codes				#
#								#
#################################################################

RESET='\033[0m'
GRAY='\033[0;37m'
WHITE='\033[1;37m'
GRAY_R='\033[39m'
WHITE_R='\033[39m'
RED='\033[1;31m' # Light Red.
GREEN='\033[1;32m' # Light Green.

#################################################################
#								#
#			   Variables				#
#								#
#################################################################

path=/opt/zeek/logs
logs=("rdp" "ssh" "http" "conn")
ydate=$(date -d "yesterday" '+%Y-%m-%d')
cdate=$(date +"%Y-%m-%d")
open_ports_count=()
ips_by_port=()
total_filter_count=0
active_count=0
inactive_count=0

#################################################################
#								#
#			Functions				#
#								#
#################################################################

#This function is used to display the green line at the top of the screen
header() {
	clear
	clear
	echo -e "${GREEN}###################################################################################################${RESET}\\n"
}

#This function is used to display the red line at the top of the screen
header_red() {
	clear
	clear
	echo -e "${RED}###################################################################################################${RESET}\\n"
}

#This function is used to dispaly the logo with text at the beginning of the script
script_logo() {
	cat << "EOF"
 ____  _  _  ___
(_   )( \/ )/ __)
 / /_  \  / \__ \
(____)  \/  (___/

Zeek Vulnerability Scanner - Version 1.0
EOF
}

#This is the first function that will be executed
start_script() {
	#Remove all the old files and directories from the previous execution
	rm -r "/tmp/zvs"
	#Create multiple directories for later use
	mkdir -p /tmp/zvs/logs 2> /dev/null
	mkdir -p /tmp/zvs/scans 2> /dev/null
	mkdir -p /tmp/zvs/tmp 2> /dev/null
	mkdir -p /tmp/zvs/report 2> /dev/null
	#Create a symbolic link between the scans and report directory
	ln -s /tmp/zvs/scans /tmp/zvs/report 2> /dev/null
	#Display the green header and logo
	header
	script_logo
	#Give a message that the script will start
	echo -e "\\n${GREEN}#${RESET} Starting the script...."
	#Wait 4 seconds
	sleep 4
}

zeek_status() {
	#Save the status of Zeek as a variable
	SERVICE_ZEEK=$(/opt/zeek/bin/zeekctl status | awk '{print $4}' | sed -n '2p')
	#Check if the service isn't  running
	if ! [ "$SERVICE_ZEEK" = 'running' ]; then
		#Display the red header
		header_red
		#Echo a message that Zeek is not running
		echo -e "${RED}#${RESET} Zeek is not running....."
		echo -e "${RED}#${RESET} Start Zeek and run the script again!"
		#Sleep for 2 seconds and exit from the script
		sleep 2
		exit
	else
		#If Zeek is running give a green header
		#And continue with the script
		header
	fi
}

read_zeek_logs() {
	#Display the green header
	header
	#Echo that the Zeek logs are being readed
	echo -e "Reading the Zeek logs\n"
	#Initiate a variable to count how many logfiles are not found
	c=0
	#Loop through the log files specified at the top of the script
	for item in "${logs[@]}"
	do
		#Declare a variable with the name of the Zeek log filename
		log_path="$path/$ydate/$item.00:00:00-00:00:00.log.gz"
		#Check if the log file exists
		if [[ -f "$log_path" ]]; 
		then
			#Echo the filename of the log as green
			echo -e "${GREEN}#${RESET} $item.log"
			#Read the logfile
			zcat $log_path | awk '{print $5}' | sort | uniq >> "/tmp/zvs/tmp/tmp_old_$cdate.txt"
		else
			#If the file is not found, echo the filename as red
			echo -e "${RED}#${RESET} $item.log"
			#Add 1 to the counter
			((c++))
		fi

		#Declase a variable with the name of the Zeek log filename
		clog_path="$path/current/$item.log"
		#Check if the log file exists
		if [[ -f "$clog_path" ]]; 
		then
			#Read the logfile
			cat $clog_path | awk '{print $5}' | sort | uniq >> "/tmp/zvs/tmp/tmp_current_$cdate.txt"
		fi
	done

	#Check if the counter is the same as the amount of files in the variable
	if ! [[ $c = "${#logs[@]}"  ]];
	then
		#If this is not the case, Wait 2 seconds
		sleep 2
	else
		#When there are no logfiles found, give a message
		echo -e "There are no Zeek logs found... Try again later"
		#Exit the script
		exit
	fi
}

filter_zeek_logs() {
	#Display the green header
	header
	#Echo a message to the user that the logs are being filtered
	echo -e "Filtering the logs\n"

	#Start a while loop to go through all the items in the file
	while read item; 
	do
		#Check if the items in the logs are a valid internal IP address (172.16.*, 192.168.*, 10.*)
		if [[ $item =~ (^127\.)|(^10\.)|(^172\.1[6-9]\.)|(^172\.2[0-9]\.)|(^172\.3[0-1]\.)|(^192\.168\.) ]]; 
		then
			#Check if the item also exists in the logs of the previous day
			if grep -Fxq "$item" /tmp/zvs/tmp/tmp_old_$cdate.txt
			then
				#Ifso add the IP to the inactive list 
				echo "$item" >> "/tmp/zvs/logs/scanlist_inactive_$cdate.txt"
				#Echo the IP address
				echo "$item"
				#Add 1 to the counter
				inactive_count=$((inactive_count+1))
				#Wait one millisecond
				sleep 0.1
			else
				#Add the IP address to the active list
				echo "$item" >> "/tmp/zvs/logs/scanlist_active_$cdate.txt"
				#Echo the IP address
				echo "$item"
				#Add 1 to the counter
				active_count=$((active_count+1))
				#Wait one millisecond
				sleep 0.1
			fi
		fi
		#Add 1 to the counter, this counter holds the amount of IP's that are being filtered
		total_filter_count=$((total_filter_count+1))
	#This is the file that is being filtered
	done < "/tmp/zvs/tmp/tmp_current_$cdate.txt"

	#Read the scanlists and filterout all duplicate IP addresses
	cat -n scanlist_active_$cdate.txt | sort -uk2 | sort -nk1 | cut -f2- > scanlist_active_$cdate.txt
	cat -n scanlist_inactive_$cdate.txt | sort -uk2 | sort -nk1 | cut -f2- > scanlist_inactive_$cdate.txt

	#Display the green header
	header
	#Echo a message for the user
	echo -e "${GREEN}#${RESET} There are in total $total_filter_count IP addresses filtered."
	echo -e "${GREEN}#${RESET} $active_count IP's have a high risk and $inactive_count IP's have a low risk."
	#A long wait of 6 seconds so the user can read the message
	sleep 6
}

nmap_installed() {
	#Check if NMAP is installed
	if ! [ -n "$(dpkg -l nmap | awk "/^ii $1/")" ];
	then
		#Display the red header
		header_red
		#Echo a message that NMAP isn't installed
		echo -e "${RED}#${RESET} Nmap is not installed..."
		echo -e "${RED}#${RESET} Install Nmap and restart the script"
		#Sleep for 3 seconds
		sleep 3
		#Exit the script
		exit
	else
		#Display the green header
		header
	fi
}

nmap_scan() {
	#Display the green header
	header
	#Echo a message for the user
	echo -e "NMAP scan started...\n"

	#Echo that the low risk clients are being scanned (inactive clients)
	echo -e "${GREEN}#${RESET} Scanning the low risk clients"
	#Execute the nmap command
	# -iL Read the file where the IP addresses are listed
	# Save as nmap-inactive using the webxml format
	# Don't give any output to the user
	# Get the processid and save as variable
	nmap -iL /tmp/zvs/logs/scanlist_inactive_$cdate.txt -oA /tmp/zvs/scans/nmap-inactive --webxml >/dev/null & PID1=$!
	#Echo message
	printf "Progress: ["
	#Check if the nmap process is active
	while kill -0 $PID1 2> /dev/null; do
		#Print for every second the process is running a dot and wait 1 second
		printf "."
		sleep 1
	done
	#When the process is finished echo a message
	printf "] done!\n\n"

	#Echo that the high risk clients are being scanned (active clients)
	echo -e "${GREEN}#${RESET} Scanning the high risk clients"
	#Execute the nmap command
	# -sV use a vuln script to scan the clients for possible vulnerabilities
	# -iL Read the file where the IP addresses are listed
	# Save as nmap-inactive using the webxml format
	# Don't give any output to the user
	# Get the processid and save as variable
	nmap -sV --script vuln -iL /tmp/zvs/logs/scanlist_active_$cdate.txt -oA /tmp/zvs/scans/nmap-active --webxml >/dev/null & PID2=$!
	#Echo message
	printf "Progress: ["
	#Check if the nmap process is active
	while kill -0 $PID2 2> /dev/null; do
		#Print for every seconds the process is running a dot and wait 1 second
		printf "."
		sleep 1
	done
	#When the process is finished echo a message
	printf "] done!\n\n"
	#Wait 3 seconds after scanning both client lists
	sleep 3
}

gather_details() {
#A variable that holds both namp result files
files=(nmap-inactive.nmap nmap-active.nmap)

#Loop through both files
for file in ${files[@]}
do
	#Check if the files exists
	if [[ -f "/tmp/zvs/scans/$file" ]]; 
	then
		#Gather all the ports
		found_ports=$(awk '
			/^[0-9]+\/tcp/{
			  sub(/\/.*/,"",$1)
			  if(!tcpVal[$1]++){ a=""    }
			}

			/^[0-9]+\/udp/{
			  sub(/\/.*/,"",$1)
			  if(!udpVal[$1]++){ a=""    }
			}

			END{
			  for(i in udpVal) { print i "/udp" }
			  for(j in tcpVal) { print j "/tcp"}
			}' /tmp/zvs/scans/$file)
		#Loop through all the ports found
		for port in ${found_ports[@]}
		do
			#Variable that holds the output if the ports is open
			count_ports_open=$(cat /tmp/zvs/scans/$file | grep -o "$port open" | wc -l)
			#If the port is open add it to the open_ports_count variable
			if ! [ $count_ports_open = 0 ];
			then
				open_ports_count+=("${port} ${count_ports_open}")
			fi

			#Get only the name of the file, remove the file extension
			name=$(echo $file | rev | cut -c6- | rev)
			#Get all the IP addresses of alle the scanned clients
			ips=$(grep -e 'open/tcp' -e 'open/udp' /tmp/zvs/scans/$name.gnmap | cut -d ' ' -f 2)
			#Loop through all the IP addresses
			for ip in ${ips[@]}
			do
				#Get the Port that beholds to the specific IP address
				if grep -A 20 $ip /tmp/zvs/scans/$name.nmap | grep "$port open" >/dev/null ;
				then
					#Save this as an array to the variable ips_by_port
					ips_by_port+=("${ip} ${port}")
				fi
			done
		done
	fi
done
}

setup_report() {
	#Display the green header
	header
	#Create the index.html file in the report directory
	touch /tmp/zvs/report/index.html
	#Place the HTML code inside the index.html file
	cat >> /tmp/zvs/report/index.html << EOF
		<!DOCTYPE html>
		<html>
  	  	  <head>
    	  	   <title>ZVS - Report</title>
    	  	   <style>
            		table {
		              font-family: arial, sans-serif;
		              border-collapse: collapse;
		              width: 100%;
            		}
		        td, th {
		              border: 1px solid #dddddd;
		              text-align: left;
		              padding: 8px;
	                }
            		tr:nth-child(even) {
		              background-color: #dddddd;
	                }
            		#report {
		              margin-left: 50px;
	                }
            	        #high_risk {
			      color: red;
			}
			#low_risk {
			      color: green;
			}
                  </style>
   	 	</head>
    		<body>
	     	 <div style='text-align:center;' id='header'>
    	<pre> ____  _  _  ___
<font color="#4E9A06">(</font>_   <font color="#4E9A06">)(</font> <font color="#4E9A06">\</font>/ <font color="#4E9A06">)</font>/ __<font color="#4E9A06">)</font>
 / /_  <font color="#4E9A06">\</font>  / <font color="#4E9A06">\</font>__ <font color="#4E9A06">\</font>
<font color="#4E9A06">(</font>____<font color="#4E9A06">)</font>  <font color="#4E9A06">\</font>/  <font color="#4E9A06">(</font>___/

</pre>
          	<p>Zeek Vulnerability Scanner - Version 1.0</p>
		</div>
		<div id='report'>
			<h1>ZVS Report</h1>
			<p>The script was initiated at <i>$(date)</i> the following results are generated from the scan.</p>

			<p>The following Zeek logs have been scanned: <span style='color:#4E9A06;'>$(echo $(echo ${logs[@]}) | tr ' ' ',')</span></p>

			<p>From the Zeek logs of today <i>$total_filter_count</i> IP's where gathered.</p>
			<p>There were <i>$active_count</i> IP's found with a higher risk for vulnerabilities, <i>$inactive_count</i> IP's had a lower risk.</p>

			<h2>NMAP Report</h2>
			<p>NMAP scanned all the clients with a high and low risk. The clients with a low risk have been scanned for open ports. <br> An extensive scan has been executed on the clients with a higher risk.</p>

			<label for='high_risk'>View namp report:</label>
			<a href='/scans/nmap-active.xml' target='_blank' id='high_risk'>High risk clients</a>
			<a href='/scans/nmap-inactive.xml' target='_blank' id='low_risk'>Low risk clients</a>

			<h2>Summary</h2>
			<p>Below are the ports shown that are detected as open.</p>

	                <table style='width:auto;'>
        	        <tr>
                	  <th>Port</th>
	                  <th>Count</th>
			</tr>
EOF
	#Loop through all the open ports
	#Create a table column for each open port
	#Display the portnumber in the first row
	#And the amount of open ports in the second row
	for result in "${open_ports_count[@]}"
	do
		port=$(echo $result | head -c -7)
		cat >> /tmp/zvs/report/index.html << EOF
		<tr>
		  <td>$(echo $result | awk '{print $1}')</td>
		  <td>$(echo $result | awk '{print $2}')</td>
		</tr>
EOF
	done

cat >> /tmp/zvs/report/index.html << EOF
	</table>
	</div>
	</body>
	</html>
EOF
}

start_http_service() {
	#Display the green header
	header
	#Echo a message to the user
	echo -e "${GREEN}#${RESET} A http server has been started on port 8000\n"
	echo -e "${GREEN}#${RESET} Visit http://localhost:8000 for the report"
	#Start a local Python http server in the specified directory
	#Use port 8000 and don't output to the user
	nohup python3 -m http.server --directory /tmp/zvs/report 8000 &> /dev/null
}

#################################################################
#								#
#			Execute Functions			#
#								#
#################################################################

start_script

zeek_status
nmap_installed

read_zeek_logs
filter_zeek_logs

nmap_scan
gather_details
setup_report

start_http_service
