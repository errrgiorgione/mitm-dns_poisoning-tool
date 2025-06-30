# What does this repo do? 
This repo was born with the goal of interacting with the networks (specifically WiFi ones). It started as a simple scanner that could show you the connected devices and some info on the network itselfs. 
To this day the code in this repo evolved to execute Man In The Middle attacks and DNS poisoning attacks, while stile being able to scan the network for its connected devices.

# Download
To download and use the code you can run the following commands on Windows command prompt:
```
git clone https://github.com/errrgiorgione/dns-mitm-tool
cd dns-mitm-tool
pip install -r requirements.txt
```
Then you can run the main.py script by calling the Python interpreter.

# Usage

## Scan the network
The following example shows a basic example to run this script in scan mode.

![nds example](https://github.com/user-attachments/assets/ec87da22-f4be-4251-a250-6954e458d3c0)

It is necessary to specify the network's IP address to start the scan, which will show the IP address, the MAC address and the name of the detected connected device. The device's name will be flagged as "Unknown" if the script failed to find its name.
Other optional arguments are: 
* -v / --verbose , which will show the packets sent by the connected devices. The packets will not be formatted.
* -t / --timeout , it specifies how long the script should wait for a response after sending each packet. On a typical home network, the script usually sends up to 255 packets.

## Run a Man In The Middle attack
To run a MITM attack you must specifies at least the following IP addresses:
* The target device's IP address
* The spoofed device's IP address, which is the device you are pretending to be
* Your device's IP address, it usually is the IP address of the device that is running the attack but it can be the IP address of any device you want to redirect the traffic to
  
![mitma example](https://github.com/user-attachments/assets/1363dddc-bbd4-419b-af18-b1dd4ab4b421)

The script will try to find the devices's MAC addresses from their IP addresses and will start to flood the network with fake ARP packets.
You can also manually specify the devices' MAC addresses. You can also modify the timeout of a few functions, the mode of the attack and if to fix the ARP tables.

I am aware that the both-ways MITM attack (which is the default mode the attack uses) triggers a "duplicated use" of both the target device's IP address and the spoofed device's IP address, which often causes the attack to fail. To this day, the one-way MITM attack is the only mode that always worked on my tests.
### Please keep in mind that a MITM attack is more efficient after a little while passed since it started and that its efficiency heavily depends on the network and devices' settings.

## Run a DNS Poisoning attack
The DNS Poisoning attack is divided in two phases which are executes simultaneously:
* Man In The Middle attack
* Injecting a fake DNS answer in the network

As this attack requires a MITM running in background, you will need to specify the same arguments as when you are running a normal MITM attack. You will also need to specify the IP address of the website you want to redirect the target device to.

![dpa example](https://github.com/user-attachments/assets/e8815d55-c4a0-483b-b466-8562f404a8c0)

The output is the same as the one returned from a normal MITM attack but the DNS Poisoning attack also outputs the DNS queries that it intercepted and answered to. In the example above, the fake DNS answers should redirect the device to Youtube.com.

To the day when I am writing this README file, I am aware that this function doesn't really accomplish its goal and, on the various tests i run, it seems like it succesfully interrupts the comunication between the target device and the spoofed device rather than redirecting the target device to some website. I am also aware that the output returned from this function is mixed and not very readable and that stopping this function is impossible unless you kill the terminal where you are running the script or the Python interpreter from the Task Manager.

## Test environment
This script was tested on a Windows 11 laptop using Python 3.10.0, most of the MITM and DNS poisoning attacks were tested by attacking an Android device while faking to be a router. Wireshark was used to monitor the traffic on my laptop.

# Final notes
I will continue to work on this script, especially on the bugs I talked about above, and if I will make any progress I will update this repo and this README file. 
Any suggestion is welcomed and this repo is set public to let everyone see and use this code.
