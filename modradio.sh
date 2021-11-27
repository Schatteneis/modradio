#!/bin/bash
mkdir -p $HOME/modradio
mkdir -p $HOME/modradio/downloaded
cd $HOME/modradio
tracknmb=0
echo Welcome to Modarchive radio!
echo commands:
echo q: quit the program
while [ true ]
do
keepfile=false
echo Getting Random MOD from Server...
wget -q -nc "https://modarchive.org/index.php?request=view_random" -O rand.txt
url=$(sed -nr '/downloads.php/ s/.*downloads.php([^"]+).*/\1/p' rand.txt)
IFS="#" read name filename <<< "$url"
echo Downloading $filename...
cd ./downloaded
wget -q "https://api.modarchive.org/downloads.php$url" -O $filename
cd ..
echo "$filename" >> $HOME/modradio/previoustracks.txt
rm rand.txt
openmpt123 --ui ./downloaded/$filename
((tracknmb++))
read -t 3 -n 1 inp
case $inp in
    q)
        echo uitting...
        break
        ;;
    *)
        echo "Played $tracknmb track(s)"
        ;;
esac
done