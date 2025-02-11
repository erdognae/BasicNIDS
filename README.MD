# Ağ Paketleri İzleme ve Zararlı IP Tespiti

Bu Python projesi, ağ üzerindeki gelen ve giden paketleri dinleyerek zararlı IP adreslerini tespit eder. Dinlenen IP adresleri, `iplist.txt` dosyasındaki zararlı IP listesi ile karşılaştırılır. Eğer bir paket, bu listede yer alan bir IP adresine sahipse, ilgili uyarılar terminale yazdırılır.

## 📌 Gereksinimler

Bu projeyi çalıştırabilmek için aşağıdaki gereksinimler sağlanmalıdır:

- **Python 3.x** sürümü yüklü olmalıdır.
- Aşağıdaki Python modülleri gereklidir:
  - `socket`: Python’un standart kütüphanesinde bulunur ve ağ bağlantıları için kullanılır.
  - `struct`: Verileri ikili formatta işlemek için kullanılır.
  - `os`: Dosya ve dizin işlemleri için kullanılır.

Gerekli modülleri yüklemek için aşağıdaki komutu çalıştırabilirsiniz:

```bash
pip install -r requirements.txt
