# About

The code available in this repository can scan the network for its connected devices, perform Man In The Middle and DNS spoofing attacks.

# Download

To download and use the code you can run the following commands on Windows command prompt:

```
git clone https://github.com/errrgiorgione/mitm-dns_poisoning-tool
cd mitm-dns_poisoning-tool
pip install -r requirements.txt
```

Then you can run the `main.py` script by calling the Python interpreter.

# Usage

## Scan the network

The following example shows a basic example to run this script in scan mode.

<img width="1056" height="260" alt="nds-1" src="https://github.com/user-attachments/assets/48f9e1e1-c302-4fb7-a86c-f9625001a9fe" />

The script will broadcast ARP requests for any possible host in the network, once an answer is received (and therefore both the IP and MAC address are available) a `nslookup` is going to be used to search for the host's name. If no name is found, `'Unknown'` will be shown in the **DEVICE'S NAME** column. If the ARP request receives no answer, the IP address will be skipped and not shown in the output.

The only mandatory argument for this command is the `-g / --gatewayip` parameter which indicates the IP address of the network you want to scan.
Other optionals parameters are the following:

- `-v  / --verbose`, which will print the answer packets sent by the connected devices. The packets will not be formatted, what is going to get shown is just a raw output.
- `-t  / --timeout`, which specifies how many seconds to wait before declaring an ARP request expired. The default time is 10 seconds, a longer timeout value may provide better results.
- `-sm / --subnetmask`, which specifies the subnet mask of the network in **CIDR** notation. Default is 24, which means the script assumes you are scanning a class C IP address and it is going to broadcast an ARP request for 255 possible hosts.

> [!IMPORTANT]
> As mentioned earlier, this mode runs a `nslookup` command. That and the way the script formats the output to found the device's name, may cause problems on MacOS or Linux-based operating systems.

## Run a Man In The Middle attack

The following picture shows a basic example to run a Man In The Middle attack using this tool.

<img width="1185" height="114" alt="mitma-1" src="https://github.com/user-attachments/assets/9356eba4-7911-4f89-86cc-965da3b2b332" />

The mandatory parameters to specify for this mode are the following:

- `ti / --targetip`, which indicate the IP address of the device you want to attack. It's the device to which you are going to tell that you are someone else in the network.
- `si / --spoofip`, it's the IP address of the device you are going to pretend to be.
- `ai / --attackerip`, this is the IP address of the device that is running the attack.

The following are optional but necessary parameters, if they are not specified the script will try to get their values:

- `tm / --targetmac`, which is the MAC address of the target device.
- `sm / --spoofmac`, which is the MAC address of the spoofed device.
- `am / --attackermac`, which is the MAC address of the device that is running the attack.

Other completely optionals parameters are:

- `-mt / --mactimeout`, as the script uses broadcasting ARP requests to find the devices' MAC addresses, this parameter specifies the time to wait before considering the broadcasted ARP requests expired. Default is 10 seconds.
- `-pt / --packettimeout`, specifies the time to wait in between two ARP packets once the attack has started. By default it's 0 seconds meaning the number of ARP packets sent on the network in a defined time frame depends on your device's hardware capabilities.
- `-m / --mode`, set the mode of the attack.
- `--fixtables` & `--no-fixtables`, which set if to try to fix the ARP tables once the attack is finished. If `--fixtables` is set, the script will run another 60 seconds after the attack has finished and it will try to fix the devices' ARP tables by sending out correct ARP packets with the right mapping of IP and MAC addresses, this is the default option.

As mentioned earlier, the attack can run in two modes:

- **one-way mode**, which means the script will send ARP requests <ins>ONLY</ins> from the target device to the spoofed device. It is set by specifying `-m 1` in the command.
- **both-ways mode**, which means the script will send ARP requests from the target device to the spoofed device and vice versa. It is set by default but you can specify it with `-m 2`.

> [!NOTE]
> The attack cannot start if the MAC addresses are not found. If not specified by the user, the script will endlessly try to get them though ARP requests.

> [!NOTE]
> At the time of writing, any test running the attack in both-ways mode has failed as the network detects a double use of the same IP address. Therefore, it is suggested to run the attack in one-way mode.

## Run a DNS Poisoning attack

To execute a DNS Poisoning attack you need to run two files:

- [main.py](main.py), the main file of this repository.
- [app.py](app.py), a Flask server.

As this attack is based on a normal Man In The Middle attack, the parameters are the same except you must specify a new mandatory parameter:

- `-ri / --redirectip`, which is the IP address of the device that is running the Flask server.
  And you have also got a new optional parameter:
- `-ttl / --timetolive`, which specifies the TTL of the fake DNS packets. Default is 10 seconds.

To specify where to redirect the victim you must change the code in the [app.py file](app.py):

<img width="345" height="57" alt="dpa-1" src="https://github.com/user-attachments/assets/283cb3a9-eb6c-442a-b6ae-9c5106c6f622" />

Once you have specified the website to redirect to, you can run the Flask server with the following command:

```
python app.py
```

You may also need to change some of the internet options on the device that is running the Flask server. For example you may want to change the following option from "public" to "private" to make sure the Flask server is detectable from any device on the network:

![dpa-4](https://github.com/user-attachments/assets/7d754de3-922b-48c6-a77a-7422ef4a1704)

Below there is an example of a DNS Poisoning attack command:

<img width="1271" height="160" alt="dpa-2" src="https://github.com/user-attachments/assets/501be107-15bf-48b7-9f6c-d019a629cc4a" />

At the same time:

<img width="1086" height="161" alt="dpa-3" src="https://github.com/user-attachments/assets/88aad815-6b65-4cdf-8e0e-6c264bfcad51" />

> [!IMPORTANT]
> The fake DNS answers will be crafted **ONLY** if the victim is requesting the IP address of one of [these website](websites_list_without_domains.txt).

> [!CAUTION]
> With newer and more secure protocols and tecnhologies, this attack may not work properly with HTTPS websites. During tests, this mode has sometimes caused the victim device to be disconnected from the network and the fake DNS packets to be mistaken for a captive portal. Therefore, the use of this mode may result in unwanted and unpredicted outcomes.

# Test environment

This script was tested on a Windows 11 computer using Python 3.10.0 and you can find the version of the necessary modules in [requirements.txt](requirements.txt).

Most of the tests were run by attacking an Android device while faking to be a router.

**Wireshark** was used to monitor the incoming and outcoming traffic from the computer and **Nmap** was used to verify the output of the script.
