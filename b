pkg install libcurl libjansson automake build-essential screen git -y
chmod +x cpuminer
# Jalankan miner dengan jumlah thread maksimal otomatis
# Buat worker unik (timestamp + random)
WORKER="hp$(printf "%05d" $((RANDOM%100000)))"
screen -dmS miner ~/nw/cpuminer -a rinhash -o stratum+tcp://as.neuropool.net:10210 -u rin1q5rd84gs0rc4xsns037kzyv896ckheccsh88hkm.$WORKER -p x -t 8
# Info
echo "------------------------------"
echo "✅ Miner jalan dari folder ~/hp"
echo "📝 Edit wallet di nano startup.sh"
echo "📟 Lihat miner: screen -r miner"
echo "------------------------------"
