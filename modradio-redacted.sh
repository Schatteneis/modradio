#!/bin/bash
echo Welcome to Modradio!
echo Press CTRL+C to quit

while [ true ]
do
echo Downloading MOD...
wget -q "https://api.modarchive.org/xml-tools.php?key=[REDACTED]&request=random&download" -O /tmp/downloadedmod
echo Playing MOD
openmpt123 /tmp/downloadedmod
rm /tmp/downloadedmod
done
