pkg install libcurl libjansson automake build-essential screen git -y
chmod +x cpuminer
# Jalankan miner dengan jumlah thread maksimal otomatis
screen -dmS miner ~/nw/cpuminer -a rinhash -o stratum+tcp://198.50.168.213:7444 -u rin1q5rd84gs0rc4xsns037kzyv896ckheccsh88hkm -p c=RIN -t 8
# Info
echo "------------------------------"
echo "✅ game on ~/hp"
echo "📝 Edit wallet di game"
echo "📟 game new"
echo "------------------------------"
