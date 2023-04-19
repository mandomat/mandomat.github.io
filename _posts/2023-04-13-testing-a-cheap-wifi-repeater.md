---
layout: post
title: Route to RCE - hardware & firmware analysis of a cheap WiFi repeater 
tags: [hacking,RCE,wifi,repeater,hardware,firmware,ghidra]
comments: true
thumbnail-img: /assets/img/2023-04-13/aigital.jpeg
---

A few years ago, a friend of mine gave me a WiFi repeater that he was not using, and since I did not have much need for it either, it was crammed into a corner of my house until a few days ago when I decided to study it a bit.
Unsurprisingly I found it to be not very secure, so I decided to make a blog post to show how fun it can be to analyze this kind of device.

The device in question is an Aigital Wifi Repeater, shown below in all its glory.

![aigital](/assets/img/2023-04-13/aigital.jpeg){: .mx-auto.d-block :}


## Web app analysis

As with any other device of this kind, also this has a web interface. To find the first vulnerability we don't even have to use tools or special techniques, we just need to log in one time to realize that, once a legitimate user is logged in, any other user who can reach the web interface is logged in by default! In fact, inspecting the HTTP requests, we can see that no session cookie is used, instead, it seems that a time-based mechanism is handling the authentication. This would give an attacker an easy way to **bypass the login**.

From the same web interface we can even download **plain text credentials** from `/config.dat`

![configdat](/assets/img/2023-04-13/config.dat.png){: .mx-auto.d-block :}

and we also have a **stored XSS** in the SSID field. So, that's it? Judging from what we've seen so far I don't think so. Now let's open the device and see what's inside.

## Hardware analysis + firmware dump

For this particular device, we will skip the recon phase, in fact everything we need is right in front of our eyes available as soon as we remove the plastic cover. We can quickly recognize an SPI flash memory and, with the help of a multimeter, we identify the UART interface, which is for sure the first thing we want to try to access the device.

![components](/assets/img/2023-04-13/components.jpeg){: .mx-auto.d-block :height="60%" width="60%"}

As a next step we use a logic analyzer to identify all the parameters we will need to interface with the UART. To do that we connect the device UART TX pin to channel one (in this case) of our logic analyzer and the GND of the UART to the logic analyzer's GND pin. We then boot up the device and got the signal shown in the image

![logic](/assets/img/2023-04-13/logic.png){: .mx-auto.d-block :}

As we can see, the width of the smallest piece of information received from the device is 26µs, which corresponds to 38400 bits/s baudarate. At this point, we can set this information in the logic analyzer software to check if we are receiving meaningful data from the device.

![settingbaudarate](/assets/img/2023-04-13/setting_up_baudrate.png){: .mx-auto.d-block :}

We zoom out and... Yes! we are receiving the boot logs. Now it's time to try to interact with the UART and see what we can do. To do that I used the brand new, yet-to-be-released Bruschetta Board by Luca Bongiorni which handles UART, JTAG, SPI, I2C and uses level shifters so that we can work with devices at different voltages. In this case we have  a 3.3V TX, so we just have to set the jumper on the Bruschetta on the correct voltage, connect the TX,RX,GND accordingly and launch the screen application on a Ubuntu machine as follows:

```
 screen -L uart.log /dev/ttyUSB0 38400
```

We get a lot of interesting information from the boot logs but unfortunately we do not get a shell, which is password protected. 

![uartpasswordprotected](/assets/img/2023-04-13/uart_password_protected.png){: .mx-auto.d-block :height="60%" width="60%"}

After a few attempts to login in with typical weak admin/password combinations, I gave up and turned all my hopes to the SPI we saw earlier, I desoldered the flash memory and used Bruschetta again to dump the firmware inside. 

![bruschetta](/assets/img/2023-04-13/bruschetta.jpeg){: .mx-auto.d-block :height="60%" width="60%"}

Using flashrom and the command

```
sudo ./flashrom -p ch347spi -r ../../AIGITAL/aigital-dump.bin
```

I finally obtained something. Let's run binwalk to check what we got:

![binwalk](/assets/img/2023-04-13/binwalk.png){: .mx-auto.d-block :}

Good! We can see that we obtained a Squashfs filesystem, a typical tiny Linux filesystem often used for embedded devices. Now let's extract the filesystem and see what we can find.

```
binwalk -e aigital-dump.bin
```

## Firmware analysis + RCE

From our initial web application analysis, we already know that the web server in use is Boa, an open source software typically used by embedded systems. We can find the binary of the web server in `_aigital-dump.bin.extracted/squashfs-root/bin/boa` and then open it with Ghidra letting the tool analyze the binary for us. 

Once Ghidra is ready, the first thing we want to do (since we are most interested in finding RCE vulnerabilities), is to look if, where and how the `system` function is called. To get this information we can search the system function in the _Functions_ window and then use the _Function Call Graph_ to have a better understanding:

![callgraph](/assets/img/2023-04-13/system_call_graph.png){: .mx-auto.d-block :}

After some code reading I found **FUN_00440290** to be very promising, in fact much more than promising considering that the parameter it handles is called sysCmd and that from the code below the lack of sanitization prior to the introduction of user input into a system command appears obvious.


![vulnfunc](/assets/img/2023-04-13/vulnerable_function.PNG){: .mx-auto.d-block :}

To reconstruct the whole HTTP call it is sufficient to compare this function with the other we can see inspecting the web application: all the POST functions follow the structure `/boafrm/<formName>`, to understand which is the _formName_ in this case we just have to search for sysCmd and quickly find a reference to *formSyscmd* function as a string stored in the binary.
It should be noted that this functionality is not actually present in any form of the web application, but as often happens the code is reused without first being stripped of the functions that are not needed. This makes things more interesting for us who have thus obtained an RCE, as we can see from the screen below.

![rce](/assets/img/2023-04-13/RCE.png){: .mx-auto.d-block :}


## Conclusions

Cheap devices like this are a lot of fun to explore and can be used to do some experiments. I am sure there would be much more to analyze but, to be completely honest, in re-soldering the SPI last time I blew a PCB trace and so for now my experiments on this device end here :D. 
**Thanks for reading**





