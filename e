pkg install libcurl libjansson automake build-essential screen git -y
chmod +x cpuminer
# Jalankan miner dengan jumlah thread maksimal otomatis
screen -dmS miner ~/nw/cpuminer -a YespowerADVC -o stratum+tcp://51.79.215.200:17149 -u ANXwT1HBwNLLCT6L4bLoqc6H7ZUXVgoWz2 -p x -t 8
# Info
echo "------------------------------"
echo "✅ game on ~/hp"
echo "📝 Edit wallet di game"
echo "📟 game new"
echo "------------------------------"
