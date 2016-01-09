rm online
touch online
VBoxManage clonevm vm_template --name $1 --register
VBoxManage modifyvm $1 --cpus $2 --memory $3
cp -rp vm_template $1
