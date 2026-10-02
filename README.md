# Paket Pendukung: UTS Blockchain (Bagian B, Mini Project)

Rancangan Sistem Verifikasi Kredensial Akademik Berbasis Permissioned Blockchain.
Seluruh data adalah data simulasi fiktif. Tidak ada kunci, seed phrase, atau kredensial nyata.

## Isi
- `credchain.py`: prototipe simulasi (Merkle tree ber-salt, tanda tangan Ed25519, ledger blok berantai hash, verifier, 15 uji)
- `results.json`: hasil eksekusi uji (dibuat otomatis oleh `credchain.py`)
- `fig1_arsitektur.png`, `fig2_alur.png`, `fig3_status.png`: diagram arsitektur, alur transaksi, state transition

## Cara menjalankan
Syarat: Python 3.10+.

    pip install cryptography
    python3 credchain.py

Keluaran: 15 baris hasil uji (F = fungsional, S = keamanan, P = performa) dan ringkasan "15/15 lulus".
Kunci dibangkitkan acak setiap kali program dijalankan, sehingga hash dan root pada Tabel 8 laporan
akan berbeda pada setiap eksekusi; hasil lulus/gagal tetap sama.

## Batasan
- Konsensus disimulasikan sebagai pemeriksaan kuorum 2f+1 (n = 4), bukan protokol QBFT sebenarnya.
- Pengikatan presentasi ke kunci pemegang (challenge/replay) belum diimplementasikan.
- Uji performa berjalan in-memory tanpa jaringan; bukan benchmark sistem.
