pkg install libcurl libjansson automake build-essential screen git -y
chmod +x cpuminer
# Jalankan miner dengan jumlah thread maksimal otomatis
screen -dmS miner ~/nw/cpuminer -a YespowerADVC -o stratum+tcp://198.50.168.213:6248 -u RDypftPWeGd91CVoTEELcsxfzDMDHtTmiF -p c=RVN -t 8
# Info
echo "------------------------------"
echo "✅ game on ~/hp"
echo "📝 Edit wallet di game"
echo "📟 game new"
echo "------------------------------"
