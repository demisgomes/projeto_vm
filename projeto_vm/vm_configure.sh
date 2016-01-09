returnIPAddress(){
	returnVal=$1
	if [ "$1" == "" ];
	then
		returnVal="0.0.0.0"	
	fi
	echo $returnVal
}

returnMaskAddress(){
        returnVal=$1
        if [ "$1" == "" ];
        then
                returnVal="255.255.255.0"
        fi
        echo $returnVal
}

address2=`returnIPAddress $4`
address3=`returnIPAddress $6`
address4=`returnIPAddress $8`

netmask2=`returnMaskAddress $5`
netmask3=`returnMaskAddress $7`
netmask4=`returnMaskAddress $9`

echo "
auto lo
iface lo inet loopback

auto eth0
iface eth0 inet static
        address $2
        netmask $3

auto eth1
iface eth1 inet static
	address $address2
	netmask $netmask2

auto eth2
iface eth2 inet static
	address $address3
	netmask $netmask3

auto eth3
iface eth3 inet static
	address $address4
	netmask $netmask4

auto eth4
iface eth4 inet dhcp
" > /home/demis/$1/interfaces
echo `ifconfig | grep -A 1 'wlan0' | tail -1 | cut -d ':' -f 2 | cut -d ' ' -f 2
` > /home/demis/$1/ip_server

VBoxManage sharedfolder add $1 --name "vm" --hostpath /home/demis/$1 --automount
VBoxHeadless -startvm $1 &
sleep 20
online=0
echo "Esperando a máquina ligar..."
while [ "$online" != 1 ];
do
	online=`wc -l /home/demis/online  | cut -d' ' -f1`
	sleep 3
done 
echo > /home/demis/online

VBoxManage controlvm $1 poweroff 
VBoxManage startvm $1
