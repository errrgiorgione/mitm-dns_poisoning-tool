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
* -t / --timeout , it specifies how long the script should wait for a response after sending each packet.
* -sm / --subnetmask , changes the subnet mask of the network.

## Run a Man In The Middle attack
To run a MITM attack you must specifies at least the following IP addresses:
* The target device's IP address
* The spoofed device's IP address, which is the device you are pretending to be
* Your device's IP address, it usually is the IP address of the device that is running the attack but it can be the IP address of any device you want to redirect the traffic to
  
![mitma example](https://github.com/user-attachments/assets/1363dddc-bbd4-419b-af18-b1dd4ab4b421)

The script will try to find the devices's MAC addresses from their IP addresses and will start to flood the network with fake ARP packets.
You can also manually specify the devices' MAC addresses. You can also modify the timeout of a few functions, the mode of the attack and if to fix the ARP tables.

I am aware that the both-ways MITM attack (which is the default mode the attack uses) triggers a "duplicated use" of both the target device's IP address and the spoofed device's IP address, which often causes the attack to fail. To this day, the one-way MITM attack is the only mode that always worked on my tests.
# Keep in mind
A MITM attack is more efficient after a little while passed since it started and that its efficiency heavily depends on the network and devices' settings.

## Run a DNS Poisoning attack
The DNS Poisoning attack is divided in three phases which are executed simultaneously:
* Man In The Middle attack
* Injecting a fake DNS answer in the network
* Flask server 

As this attack requires a MITM running in background, you will need to specify the same arguments as when you are running a normal MITM attack. You will also need to specify the IP address of the device that is running the Flask server.

![dpa example](https://github.com/user-attachments/assets/fec9dda6-1c14-4ea8-9310-120e528559d5)

The output is the same as the one returned from a normal MITM attack and the DNS poisoning attack itselfs doesn't have any output.

At the same time, you will need to run the Flask server in the app.py file in another terminal with the following command:
```
python app.py
```
You can run the Flask server on the same device or on any other device that is connected to the network. The -ri argument needs to be the IP address of the device that is running the Flask server.

## How it works
The fake DNS answers crafted by the main.py script will redirect the attacked device to the device where the Flask server is running. The Flask server will redirect the attacked device to the website you specified in the Flask server script (by default there is no specified website to redirect to).

## Keep in mind
The fake DNS answers will be crafted only if the attacked device is asking for one of the IP addresses contained in the dns-mitm-tool\websites_list_without_domains.txt list.  

You may also need to set the device running the Flask server detectable on the network:

![network profile type windows 11](https://github.com/user-attachments/assets/f59ff4dc-8d1b-48d0-9ca1-f8c0ea088604)
If it is set to "public" change it to "private".

# Test environment
This script was tested on a Windows 11 laptop using Python 3.10.0, most of the MITM and DNS poisoning attacks were tested by attacking an Android device while faking to be a router. Wireshark was used to monitor the traffic on the laptop.

# Final notes
I will continue to work on this script, especially on the bugs I talked about above, and if I will make any progress I will update this repo and this README file. 
Any suggestion is welcomed and this repo is set public to let everyone see and use this code.
