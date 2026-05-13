# Ozip Decrypt

Strumento per decrittografare file `.ozip` proprietari Oppo, trasformandoli in file `.zip` standard.

## Come funziona

I file `.ozip` sono archivi ZIP cifrati con AES-128-ECB. Il formato prevede:

- Un header di 12 byte con la stringa magica `OPPOENCRYPT!`
- Blocchi da 16 byte cifrati, intervallati da blocchi da 16384 byte in chiaro

La chiave di cifratura è una stringa esadecimale che varia in base al modello del dispositivo.

## Requisiti

- OpenSSL (`libssl-dev` su Linux, pacchetto `openssl` su MSYS2/MinGW)

## Compilazione

```bash
g++ ozip_decrypt.cpp -o ozipdecrypt -lssl -lcrypto
```

Su Windows con MSYS2/MinGW:

```bash
g++ ozip_decrypt.cpp -o ozipdecrypt.exe -lssl -lcrypto
```

## Utilizzo

```bash
./ozipdecrypt <chiave_hex> <file.ozip>
```

Esempio:

```bash
./ozipdecrypt 6A4B3C8D1E2F5A7B9C0D3E4F5A6B7C8D firmware.ozip
```

Se il file non è un `.ozip` valido (manca l'header `OPPOENCRYPT!`), verrà semplicemente rinominato in `.zip`.

## Output

Il programma produce un file `.zip` con lo stesso nome del file originale (es. `firmware.ozip` → `firmware.zip`), salvato nella stessa directory.

## Licenza

GNU General Public License v3.0 — vedi l'intestazione del file sorgente.
