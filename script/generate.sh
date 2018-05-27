if [ "$#" -ne 1 ]; then
    echo "1 parametro1: <quantidade de execuções>"
    return
fi

execucoes=$1

echo Inicando com "$execucoes" execuções
for i in $(seq 1 $execucoes)
do
	img_name="server-img-$i"
	openstack image create --disk-format qcow2 --file trusty-server-cloudimg-amd64-disk1.img --public $img_name
	python3 main.py monitor -i $iface -sc -vm 1 -vi $img_name
	openstack server delete vm1
	openstack network delete local
	openstack image delete $img_name
done
