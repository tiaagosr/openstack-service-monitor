if [ "$#" -ne 2 ]; then
    echo "2 parametros: <networkIface> <quantidade de execuções>"
    return
fi

execucoes=$2
iface=$1

echo Executando análise na interface "$iface", com "$execucoes" execuções
for i in $(seq 1 $execucoes)
do
	img_name="server-img-$i"
	python3 main.py analysis -m bandwidth api -p "resultados/exec_$i.pcap" -i $iface
done
