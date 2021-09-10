#!/bin/bash
tracknmb=0
echo Welcome to Modarchive radio!
echo commands:
echo q: quit the program
echo k: keep the downloaded file
while [ true ]
do
keepfile=false
echo Getting Random MOD from Server...
wget -q -nc "https://modarchive.org/index.php?request=view_random" -O rand.txt
url=$(sed -nr '/downloads.php/ s/.*downloads.php([^"]+).*/\1/p' rand.txt)
IFS="#" read name filename <<< "$url"
echo Downloading $filename...
wget -q "https://api.modarchive.org/downloads.php$url" -O $filename
echo "$filename" >> ~/previoustracks.txt
rm rand.txt
openmpt123 --ui $filename
((tracknmb++))
read -t 3 -n 1 inp
case $inp in
    q)
        echo Quitting...
        rm $filename
        break
        ;;
    k)
        keepfile=true
        echo eeping file...
        echo "Played $tracknmb track(s)"
        ;;
    *)
        echo "Played $tracknmb track(s)"
        ;;
esac
if [ "$keepfile" = false ]
then
    rm $filename
fi
if [ "$keepfile" = true ]
then
    mv $filename ~/HDD/mods/$filename
fi

done