# What does this repo do? 
This repo was born with the goal of interacting with the networks (specifically WiFi ones). It started as a simple scanner that could show you the connected devices and some info on the network itselfs. 
To this day the code in this repo evolved to execute Man In The Middle attacks and Packet Injections attacks, while stile being able to scan the network for its connected devices.

# Usage

## Scan the network
The following example shows a basic example to run this script in scan mode.

![nds example](https://github.com/user-attachments/assets/ec87da22-f4be-4251-a250-6954e458d3c0)

It is necessary to specify the network's IP address to start the scan, which will show the IP address, the MAC address and the name of the detected connected device. The device's name will be flagged as "Unknown" if the script failed to find its name.
Other optional arguments are: 
* -v / --verbose , which will show the packets sent by the connected devices. The packets will not be formatted.
* -t / --timeout , which will declare for how long shall the script listen for each packet it sends (on a normal house network, it usually sends 255 packets).

## Run a Man In The Middle attack
To run a MITM attack you must specifies at least the following IP addresses:
* The target device's IP address
* The spoofed device's IP address, which is the device you are pretending to be
* Your device's IP address, it usually is the IP address of the device that is running the attack but it can be the IP address of any device you want to redirect the traffic to
  
![mitma example](https://github.com/user-attachments/assets/1363dddc-bbd4-419b-af18-b1dd4ab4b421)

The script will try to find the device's MAC addresses from their IP addresses and will start to flood the network with fake ARP packets.
You can also manually specify the devices' MAC addresses. You can also modify the timeout of a few functions, the mode of the attack and if to fix the ARP tables.

### Please keep in mind that a MITM attack is more efficient when it is left running for a little while and that its efficiency heavily depends on the network and devices' settings.
