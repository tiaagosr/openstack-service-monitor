if [ "$#" -ne 2 ]; then
    echo "2 parametros: <networkIface> <quantidade de execuções>"
    return
fi

mkdir -p resultados

execucoes=$2
iface=$1

echo Inicando execução na interface "$iface", com "$execucoes" execuções
for i in $(seq 1 $execucoes)
do
	img_name="server-img-$i"
	openstack image create --disk-format qcow2 --file trusty-server-cloudimg-amd64-disk1.img --public $img_name
	sleep 10
	python3 main.py monitor -o "resultados/exec_$i" -i $iface -sc -vm 1 -vi $img_name
	sleep 10
	openstack server delete vm1
	openstack network delete local
	openstack image delete $img_name
done
