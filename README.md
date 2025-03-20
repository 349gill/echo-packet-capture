
# Echo Packet Capture

This project aims to capture and analyze the internet traffic concering an Amazon Echo device using Wireshark.

In order to process packets addressed to all devices on the network, a Wi-Fi adapter must be set to [promiscuous](https://en.wikipedia.org/wiki/Promiscuous_mode) mode.

This requires a special type of Wi-Fi chip which supports eavesdropping packets(in promiscuous or monitor mode), I am using the in-built network card for the MacBook Pro for this project. To check if your network chip supports promiscuous mode on Windows, use command prompt and use the following command:
```
netsh wlan show all
```
It is tricker to check this capability on macOS, however, Wi-Fi adapters for Macbooks usually always support promiscuous mode.

To start a live capture: Open Wireshark, Go to Capture > Options and choose **e0** and enable Promiscuous Mode. Start a live capture and if you see packets being tracked which do not have the same MAC address as your device, you're probably on the right track.

By default, Wireshark will capture all packets sent or recieved by the devices on your network and on the same channel as your network adapter.