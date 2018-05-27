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
	sleep 5
	python3 main.py monitor -o "resultados/exec_$i" -i $iface
	sleep 5
done
