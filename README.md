# Wif - A WiFi packet sniffer
(pronounced like "whiff". get it?)

## Usage

### Installing
Build from source with `gcc -lpcap wif.c -o wif` (need `libpcap` installed (already pre-installed on macOS)) or install with Homebrew: `brew install quackduck/tap/wif`

### Running
Wif works by putting your default interface in monitor mode. This requires the WiFi interface to not be connected to a network. This means that you must disconnect from the WiFi network you're connected to before using Wif.

Usage is easy. Just run `./wif` (you may need `sudo` to capture packets). No arguments or options. Wif prints all packets that are heading to devices from the router, keeps track of SSIDs found, and shows two tables of information: one for devices that shows the BSSID they're connected to, the SSID (if detected), the last frame control field of the packet, the relative share of all traffic with a bar plot, and one for BSSIDs to SSIDs with a field for whether the network is encrypted or not.

Wif also saves a `wif.pcap` file in the working directory that can be used for later analysis.
### Channel & channel width
**Important:** Wif can't setup the channel or channel width to listen on: you need to find out how to do this on your OS

On macOS, most people use the aiport CLI to do this. However, airport doesn't allow adjusting the channel width, which is a major flaw. For this reason, I recommend using [chanch](https://github.com/quackduck/chanch), a CLI dedicated to channel changing on macOS that fixes this issue.

## Examples

This packet was destined for a computer that was visiting an HTTP website on an unencrypted network. (Don't worry, I own both the computer and the network)
![image](https://github.com/quackduck/wif/assets/38882631/24ae29a9-d187-4427-9538-c36cb9c0f6b8)

This image shows the two tables of data that Wif presents.
![image](https://github.com/quackduck/wif/assets/38882631/0ef63522-6d84-419d-b17e-c998ce567334)

An example with the new barplot feature:
![image](https://github.com/quackduck/wif/assets/38882631/427ab757-c2d8-4f29-83a8-9eb3252d8d5f)


## Disclaimer

Wif was made for educational purposes (I learnt so much making this thing, it's unbelievable) and is intended to be used for educational purposes. _I absolve myself of responsibility for any legal trouble you get into for using this tool._

### [Report bugs and issues here](https://github.com/quackduck/wif/issues)




