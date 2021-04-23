make

KEYSIZE=$1

if [ "$#" -eq  "0" ]
then
    echo "ERROR Usage: ./experiments <keysize>"
    exit
fi

rm results_$KEYSIZE.txt

echo "### Check results_$KEYSIZE.txt file for results ###"

for i in $(seq 1 100);do
    echo "Run $i"
    ./app $KEYSIZE >> results_$KEYSIZE.txt
    python3 generate_trace2.py $KEYSIZE page_faults.txt >> results_$KEYSIZE.txt
done

echo "### Printing stats ###"
python3 analyse_results.py results_$KEYSIZE.txt