# IoT-and-OT-Hacking
The objective of the lab is to perform IoT and OT platform hacking and other tasks that include, but are not limited to:  
- Performing IoT and OT device footprinting
- Capturing and analyzing traffic between IoT devices
- Performing IoT attacks

Using the IoT and OT hacking methodology, an attacker acquires information using techniques such as information gathering, attack surface area identification, and vulnerability scanning, and uses such information to hack the target device and network.
The following are the various phases of IoT and OT device hacking:
 - Information gathering
 - Vulnerability scanning
 - Launch attacks
 - Gain remote access
 - Maintain access

Ethical hackers or pen testers use numerous tools and techniques to hack the target IoT and OT platforms. Recommended labs that i used in learning various IoT platform hacking techniques include:

1. Perform footprinting using various footprinting techniques
 - Gather information using online footprinting tools

2. Capture and analyze IoT device traffic
 - Capture and analyze IoT traffic using Wireshark

3. Perform IoT Attacks
 - Perform replay attack on CAN protocol

# Lab 1: Perform Footprinting using Various Footprinting Techniques
Footprinting techniques are used to collect basic information about the target IoT and OT platforms to exploit them. Information collected through footprinting techniques includes IP address, hostname, ISP, device location, banner of the target IoT device, FCC ID information, certification granted to the device, etc.

Task 1: Gather Information using Online Footprinting Tools
The information regarding the target IoT and OT devices can be acquired using various online sources such as Whois domain lookup, advanced Google hacking, and Shodan search engine. The gathered information can be used to scan the devices for vulnerabilities and further exploit them to launch attacks.

1. Launch any web browser, go to https://www.whois.com/whois (here, we are using Mozilla Firefox).
2. The Whois Domain Lookup page appears; type www.oasis-open.org in the search field and click SEARCH.
![image alt](https://github.com/asyrafzf95/IoT-and-OT-Hacking/blob/559c826df66ece80263f98566eea583c8c43fcbe/images/1.jpg)
3. The result appears, displaying the following information, as shown in the screenshots: Domain Information, Registrant Contact, and Raw Whois Data.
![image alt](https://github.com/asyrafzf95/IoT-and-OT-Hacking/blob/559c826df66ece80263f98566eea583c8c43fcbe/images/2.jpg)
4. Now, open a new tab, and go to https://www.exploit-db.com/google-hacking-database.
5. The Google Hacking Database page appears; type SCADA in the Quick Search field and press Enter.
6. The result appears, which displays the Google dork related to SCADA, as shown in the screenshot.
![image alt](https://github.com/asyrafzf95/IoT-and-OT-Hacking/blob/559c826df66ece80263f98566eea583c8c43fcbe/images/3.jpg)
7. Now, we will use the dorks obtained in the previous step to query results in Google.
8. Open a new tab and go to https://www.google.com. In the search field, enter "login" intitle:"scada login".
9. The search result appears; click any link (here, SEAMTEC SCADA login).
10. The SEAMTEC SCADA login page appears, as shown in the screenshot.
![image alt](https://github.com/asyrafzf95/IoT-and-OT-Hacking/blob/559c826df66ece80263f98566eea583c8c43fcbe/images/4.jpg)
11. Similarly, you can use advanced search operators such as intitle:"index of" scada to search sensitive SCADA directories that are exposed on sites.
12. Now, in the browser window, open a new tab and go to https://account.shodan.io/login.
13. The Login with Shodan page appears; enter your username and password in the Username and Password fields, respectively; and click Login.
![image alt](https://github.com/asyrafzf95/IoT-and-OT-Hacking/blob/559c826df66ece80263f98566eea583c8c43fcbe/images/5.jpg)
14. The Account Overview page appears, which displays the account-related information. Click on Shodan on top-left corner of the window to go to the main page of Shodan.
15. The Shodan main page appears; type port:1883 in the address bar and press Enter.
![image alt](https://github.com/asyrafzf95/IoT-and-OT-Hacking/blob/559c826df66ece80263f98566eea583c8c43fcbe/images/6.jpg)
16. The result appears, displaying the list of IP addresses having port 1883 enabled.
17. Click on any IP address to view its detailed information.
![image alt](https://github.com/asyrafzf95/IoT-and-OT-Hacking/blob/559c826df66ece80263f98566eea583c8c43fcbe/images/7.jpg)
18. Detailed results for the selected IP address appears, displaying information regarding Ports, Services, Hostnames, ASN, etc. as shown in the screenshot.
![image alt](https://github.com/asyrafzf95/IoT-and-OT-Hacking/blob/559c826df66ece80263f98566eea583c8c43fcbe/images/8.jpg)
19. Similarly, you can gather additional information on a target device using the following Shodan filters:
 - Search for Modbus-enabled ICS/SCADA systems:
   port:502
 - Search for SCADA systems using PLC name:
   "Schneider Electric"
 - Search for SCADA systems using geolocation:
   SCADA Country:"US"
20. Using Shodan, you can obtain the details of SCADA systems that are used in water treatment plants, nuclear power plants, HVAC systems, electrical transmission systems, home heating systems, etc.

# Lab 2: Capture and Analyze IoT Device Traffic
Many IoT devices such as security cameras host websites for controlling or configuring cameras from remote locations. These websites mostly implement the insecure HTTP protocol instead of the secure HTTPS protocol and are, hence, vulnerable to various attacks. If the cameras use the default factory credentials, an attacker can easily intercept all the traffic flowing between the camera and web applications and further gain access to the camera itself. Attackers can use tools such as Wireshark to intercept such traffic and decrypt the Wi-Fi keys of the target network.

Task 1: Capture and Analyze IoT Traffic using Wireshark
Wireshark is a free and open-source packet analyzer. It facilitates network troubleshooting, analysis, software and communications protocol development, and education. It is used to identify the target OS and sniff/capture the response generated from the target machine to the machine from which a request originates.
MQTT is a lightweight messaging protocol that uses a publish/subscribe communication pattern. Since the protocol is meant for devices with a low-bandwidth, it is considered ideal for machine-to-machine (M2M) communication or IoT applications. We can create virtual IoT devices over the virtual network using the Bevywise IoT simulator on the client side and communicate these devices to the server using the MQTT Broker web interface. This interface collects data and displays the status and messages of connected devices over the network.
Here, i use Wireshark to capture and analyze traffic between IoT devices.

1. To install the MQTT Broker on the Windows Server 2019, click Windows Server 2019 to launch Windows Server 2019 machine.
2. Navigate to Z:\CEHv13 Module 18 IoT and OT Hacking\Bevywise IoT Simulator folder and double-click on the Bevywise_MQTTRoute_4.exe file.
3. If Open File - Security Warning popup appears, click Run.
4. The Setup - MQTTRoute 4.0 window opens. Select I accept the agreement and click on Next. Follow the wizard driven steps to install the tool.
5. After the installation completes, click on Finish. Ensure that Launch MQTTRoute is checked.
6. The MQTTRoute will execute and the command prompt will appear. You can see the TCP port using 1883.
![image alt](https://github.com/asyrafzf95/IoT-and-OT-Hacking/blob/559c826df66ece80263f98566eea583c8c43fcbe/images/9.jpg)
7. We have installed MQTT Broker successfully and leave the Bevywise MQTT running.
8. To create IoT devices, we must install the IoT simulator on the client machine.
9. Click Windows Server 2022 to switch to Windows Server 2022 machine.
10. Navigate to Z:\CEHv13 Module 18 IoT and OT Hacking\Bevywise IoT Simulator folder and double-click on the Bevywise_IoTSimulator_3.exe file.
11. If Open File - Security Warning popup appears, click Run..
12. The Setup-IoTSimulator_3 3.0 setup wizard opens. Select I accept the agreement and follow the wizard driven steps.
13. To complete the installation, select Yes, restart the computer now and click on Finish to complete the installation.
14. After restarting, Bevywise IoT Simulator is installed successfully. To launch the IoT simulator, navigate to the C:\Bevywise\IotSimulator\bin directory and double-click on the runsimulator.bat file.
15. Upon double-clicking the runsimulator.bat file opens in the command prompt. If How do you want to open this? pop-up appears, select Microsoft Edge browser and click OK to open the URL http://127.0.0.1:9000/setnetwork?network=HEALTH_CARE.
16. The web interface of the IoT Simulator opens in Edge browser. In the IoT Simulator, you can view the default network named HEALTH_CARE and several devices.
![image alt](https://github.com/asyrafzf95/IoT-and-OT-Hacking/blob/559c826df66ece80263f98566eea583c8c43fcbe/images/10.jpg)
17. Next, we will create a virtual IoT network and virtual IoT devices. Click on the menu icon and select the +New Network option.
![image alt](https://github.com/asyrafzf95/IoT-and-OT-Hacking/blob/559c826df66ece80263f98566eea583c8c43fcbe/images/11.jpg)
18. The Create New Network popup appears. Type any name (here, CEH_FINANCE_NETWORK) and description. Click on Create.
![image alt](https://github.com/asyrafzf95/IoT-and-OT-Hacking/blob/559c826df66ece80263f98566eea583c8c43fcbe/images/12.jpg)
19. In the next screen, we will setup the Simulator Settings. Set the Broker IP Address as 10.10.1.19 (the IP address of the Windows Server 2019 ). Since we have installed the Broker on the web server, the created network will interact with the server using MQTT Broker. Do not change default settings and click on Save.
![image alt](https://github.com/asyrafzf95/IoT-and-OT-Hacking/blob/559c826df66ece80263f98566eea583c8c43fcbe/images/13.jpg)
20. To proceed with the network creation, click on Yes.
21. To add IoT devices to the created network, click on the Add blank Device button.
![image alt](https://github.com/asyrafzf95/IoT-and-OT-Hacking/blob/559c826df66ece80263f98566eea583c8c43fcbe/images/14.jpg)
22. The Create New Device popup opens. Type the device name (here, we use Temperature_Sensor), enter Device Id (here, we use TS1), provide a Description and click on Save.
![image alt](https://github.com/asyrafzf95/IoT-and-OT-Hacking/blob/559c826df66ece80263f98566eea583c8c43fcbe/images/15.jpg)
23. The device will be added to the CEH_FINANCE_NETWORK.
![image alt](https://github.com/asyrafzf95/IoT-and-OT-Hacking/blob/559c826df66ece80263f98566eea583c8c43fcbe/images/16.jpg)
24. To connect the Network and the added devices to the server or Broker, click on the Start Network red color circular icon in right corner.
![image alt](https://github.com/asyrafzf95/IoT-and-OT-Hacking/blob/559c826df66ece80263f98566eea583c8c43fcbe/images/17.jpg)
25. When a connection is established between the network and the added devices and the web server or the MQTT Broker, the red button turns into green.
![image alt](https://github.com/asyrafzf95/IoT-and-OT-Hacking/blob/559c826df66ece80263f98566eea583c8c43fcbe/images/18.jpg)
26. Next, switch to the Windows Server 2019 machine. Open a web browser, and go to http://localhost:8080 and login using admin/admin (here, we are using Firefox Browser).
![image alt](https://github.com/asyrafzf95/IoT-and-OT-Hacking/blob/559c826df66ece80263f98566eea583c8c43fcbe/images/19.jpg)
27. Since the Broker was left running, you can see a connection request from machine 10.10.1.22 for the device TS1 under Recent Connections section.
![image alt](https://github.com/asyrafzf95/IoT-and-OT-Hacking/blob/559c826df66ece80263f98566eea583c8c43fcbe/images/20.jpg)
28. Switch back to Windows Server 2022 machine.
29. Next, we will create the Subscribe command for the device Temperature_Sensor.
30. Click on the Plus icon in the top right corner and select the Subscribe to Command option.
![image alt](https://github.com/asyrafzf95/IoT-and-OT-Hacking/blob/559c826df66ece80263f98566eea583c8c43fcbe/images/21.jpg)
31. The Subscribe for command - TS1 popup opens. Select On start under the Subscribe on tab, type High_Tempe under the Topic tab, and select 1 Atleast once below the Qos option. Click on Save.
![image alt](https://github.com/asyrafzf95/IoT-and-OT-Hacking/blob/559c826df66ece80263f98566eea583c8c43fcbe/images/22.jpg)
32. Scroll down the page, you can see the Topic added under the Subscribe to Commands section.
![image alt](https://github.com/asyrafzf95/IoT-and-OT-Hacking/blob/559c826df66ece80263f98566eea583c8c43fcbe/images/23.jpg)
33. Next, we will capture the traffic between the virtual IoT network and the MQTT Broker to monitor the secure communication.
34. Minimise the Edge browser. Click Type here to search field on the Desktop, search for wireshark in the search bar and select Wireshark from the results.
35. The Wireshark Application window appears, select the Ethernet as interface.
![image alt](https://github.com/asyrafzf95/IoT-and-OT-Hacking/blob/559c826df66ece80263f98566eea583c8c43fcbe/images/24.jpg)
36. Click on the Start Wireshark icon to start the capturing packets, leave the Wireshark running.
37. Leave the IoT simulator running and switch to the Windows Server 2019 machine.
38. Navigate to Devices menu and click on connected device i.e.TS1
![image alt](https://github.com/asyrafzf95/IoT-and-OT-Hacking/blob/559c826df66ece80263f98566eea583c8c43fcbe/images/25.jpg)
39. Now, we will send the command to TS1 using the High_Tempe topic.
40. In Send Command section, select Topic as High_Tempe, type Alert for High Temperature in Message field and click on the Submit button.
![image alt](https://github.com/asyrafzf95/IoT-and-OT-Hacking/blob/559c826df66ece80263f98566eea583c8c43fcbe/images/26.jpg)
41. Message sent to TS1 appears under Message box which indicates that the message was successfully sent to TS1.
![image alt](https://github.com/asyrafzf95/IoT-and-OT-Hacking/blob/559c826df66ece80263f98566eea583c8c43fcbe/images/27.jpg)
42. The message has been sent to the device using this topic.
43. Next, switch to Windows Server 2022 machine.
44. We have left the IoT simulator running in the web browser. To see the alert message, maximise the Edge browser and expand the arrow under the connected Temperature_Sensor, Device Log section.
45. You can see the alert message "Alert for High Temperature"
![image alt](https://github.com/asyrafzf95/IoT-and-OT-Hacking/blob/559c826df66ece80263f98566eea583c8c43fcbe/images/28.jpg)
46. To verify the communication, we have executed Wireshark application, switch to the Wireshark traffic capturing window.
47. Type mqtt under the filter field and press Enter. To display only the MQTT protocol packets.
![image alt](https://github.com/asyrafzf95/IoT-and-OT-Hacking/blob/559c826df66ece80263f98566eea583c8c43fcbe/images/29.jpg)
48. Select any Publish Message packet from the Packet List pane. In the Packet Details pane at the middle of the window, expand the Transmission Control Protocol, MQ Telemetry Transport Protocol, and Header Flags nodes.
49. Under the MQ Telemetry Transport Protocol nodes, you can observe details such as Msg Len, Topic Length, Topic, and Message.
50. Publish Message can be used to obtain the message sent by the MQTT client to the broker.
![image alt](https://github.com/asyrafzf95/IoT-and-OT-Hacking/blob/559c826df66ece80263f98566eea583c8c43fcbe/images/30.jpg)
51. Select any Publish Release packet from the Packet List pane. In the Packet Details pane at the middle of the window, expand the Transmission Control Protocol, MQ Telemetry Transport Protocol, and Header Flags nodes.
52. Under the MQ Telemetry Transport Protocol nodes, you can observe details such as Msg Len, Message Type, Message Identifier.
![image alt](https://github.com/asyrafzf95/IoT-and-OT-Hacking/blob/559c826df66ece80263f98566eea583c8c43fcbe/images/31.jpg)
53. Now, scroll down, look for the Publish Complete packet from the Packet List pane, and click on it. In the Packet Details pane at the middle of the window, expand the Transmission Control Protocol, MQ Telemetry Transport Protocol, and Header Flags nodes.
54. Under the MQ Telemetry Transport Protocol nodes, you can observe details such as Msg Len and Message Identifier.
![image alt](https://github.com/asyrafzf95/IoT-and-OT-Hacking/blob/559c826df66ece80263f98566eea583c8c43fcbe/images/32.jpg)
55. Now, scroll down, look for the Publish Received packet from the Packet List pane, and click on it. In the Packet Details pane at the middle of the window, expand the Transmission Control Protocol, MQ Telemetry Transport Protocol, and Header Flags nodes.
56. Under the MQ Telemetry Transport Protocol nodes, you can observe details such as Message Type, Msg Len and Message Identifier.
![image alt](https://github.com/asyrafzf95/IoT-and-OT-Hacking/blob/559c826df66ece80263f98566eea583c8c43fcbe/images/33.jpg)
57. Similarly you can select Ping Request, Ping Response and Publish Ack packets and observe the details.

# Lab 3: Perform IoT Attacks

Task 1: Perform Replay Attack on CAN Protocol
The Controller Area Network (CAN) protocol is a robust communication system that allows microcontrollers and devices to interact without a central computer. It uses a message-based approach for reliable data exchange, even in noisy environments. CAN is widely used in automotive industry due to its reliability and simplicity. In modern vehicles, CAN protocol is central to system communication, enabling connections between engine controls, brakes, and infotainment units. However, this interconnectivity can be exploited by hackers to manipulate vehicle functions, posing safety risks.
Here, i am using the ICSim tool to simulate CAN protocol and demonstrate how attackers sniff the transmitted packets and perform replay attack to gain basic control over the target.

1. Click Ubuntu to switch to the Ubuntu machine
2. In the Ubuntu machine, open a Terminal window and execute sudo su to run the programs as a root user.
3. The can-utils package is already installed on the system.
4. Now, to setup a virtual CAN interface issue following commands:
 - sudo modprobe can
 - sudo modprobe vcan
 - sudo ip link add dev vcan0 type vcan
 - sudo ip link set up vcan0
![image alt](https://github.com/asyrafzf95/IoT-and-OT-Hacking/blob/559c826df66ece80263f98566eea583c8c43fcbe/images/34.jpg)
5. To check whether Virtual CAN interface is setup successfully, run ifconfig. Here, vcan0 interface is present which confirms that our Virtual CAN interface is setup successfully.
![image alt](https://github.com/asyrafzf95/IoT-and-OT-Hacking/blob/559c826df66ece80263f98566eea583c8c43fcbe/images/35.jpg)
6. Run chmod -R 777 ICSim to give permissions to the ICSim folder.
7. Now, run cd ICSim to navigate to ICSim directory and execute make command to create two executable files for IC Simulator and CANBus Control Panel.
![image alt](https://github.com/asyrafzf95/IoT-and-OT-Hacking/blob/559c826df66ece80263f98566eea583c8c43fcbe/images/36.jpg)
8. Run ./icsim vcan0 to start the ICSim simulator. You will see the IC Simulator interface as shown in the screenshot.
![image alt](https://github.com/asyrafzf95/IoT-and-OT-Hacking/blob/559c826df66ece80263f98566eea583c8c43fcbe/images/37.jpg)
9. Open a new terminal tab and execute sudo su to run the programs as a root user (When prompted, enter the password toor). Navigate to ICSim directory to do so run cd ICSim/.
10. Execute ./controls vcan0 to start the CANBus Control Panel. You will see the CANBus Control Panel interface as shown in the screenshot.
![image alt](https://github.com/asyrafzf95/IoT-and-OT-Hacking/blob/559c826df66ece80263f98566eea583c8c43fcbe/images/38.jpg)
11. Now, we will start sniffer to capture the traffic sent to the ICSim Simulator by CANBus control panel simulator. To do so, open a new terminal tab and execute sudo su to run the programs as a root user (When prompted, enter the password toor). Navigate to ICSim directory to do so run cd ICSim/.
12. Execute cansniffer -c vcan0 to start sniffing on the vcan0 interface. Leave this sniffer on.
![image alt](https://github.com/asyrafzf95/IoT-and-OT-Hacking/blob/559c826df66ece80263f98566eea583c8c43fcbe/images/39.jpg)
13. Open a new terminal and execute sudo su to run the programs as a root user (When prompted, enter the password toor). Navigate to ICSim directory to do so run cd ICSim/. To capture the logs run candump -l vcan0.
14. After starting to capture the logs, open ICSim and Controller simulator and perform functions such as acceleration, turning left/right, opening and locking doors so that logs are generated. Once you are done, terminate the ongoing process by pressing Ctrl + C.
![image alt](https://github.com/asyrafzf95/IoT-and-OT-Hacking/blob/559c826df66ece80263f98566eea583c8c43fcbe/images/40.jpg)
![image alt](https://github.com/asyrafzf95/IoT-and-OT-Hacking/blob/559c826df66ece80263f98566eea583c8c43fcbe/images/41.jpg)
15. Now verify if you have obtained the log file by executing ls command. The .log file has been generated as shown in the screenshot.
![image alt](https://github.com/asyrafzf95/IoT-and-OT-Hacking/blob/559c826df66ece80263f98566eea583c8c43fcbe/images/42.jpg)
16. Now, to perform replay attack, run canplayer -I candump-2024-05-07_063502.log and press enter.
![image alt](https://github.com/asyrafzf95/IoT-and-OT-Hacking/blob/559c826df66ece80263f98566eea583c8c43fcbe/images/43.jpg)


