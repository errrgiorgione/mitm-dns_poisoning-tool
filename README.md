# What does this repo do? 
This repo was born with the goal of interacting with the networks (specifically WiFi ones). It started as a simple scanner that could show you the connected devices and some info on the network itselfs. 
To this day the code in this repo evolved to execute Man In The Middle attacks and Packet Injections attacks, while stile being able to scan the network for its connected devices.

# Usage

## Scan the network
The following example shows a basic example to run this script in scan mode.
![nds example](https://github.com/user-attachments/assets/569896c5-2ba9-4cad-a8e3-82f22f8bd0ff)

It is necessary to specify the network's IP address to start the scan, which will show the IP address, the MAC address and the name of the detected connected device. The device's name will be flagged as "Unknown" if the script failed to find its name.
Other optional arguments are: 
* -v / --verbose , which will show the packets sent by the connected devices. The packets will not be formatted.
* -t / --timeout , which will declare for how long shall the script listen for each packet it sends (on a normal house network, it usually sends 255 packets).
