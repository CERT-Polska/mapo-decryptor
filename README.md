# MAPO Decryptor

### Note this is only a client decryptor script, in order to recover the key please use the mapo service at https://mapo.cert.pl/ or contact us at [info@cert.pl](mailto:info@cert.pl)

## Currently supported versions


| Readme filename 	| Encrypted extensions 	|
|-----------------	|----------------------	|
| `MAPO-Readme.txt` 	| `.mapo`                	|
| `DETO-README.txt` 	| `.deto`                	|
| `MBIT-INFO.txt`   	| `.mbit`                	|
| `DANTE-INFO.txt`  	| `.dante`                	|
| `EDAB-Readme.txt` 	| `.edab`, `.edab1`        	|


## Requirements

 * [pycrypto](https://pypi.org/project/pycrypto/)


## Building an exe binary using PyInstaller

Probably needs 32bit Python

```bash
python.exe -m PyInstaller --manifest decryptor.exe.manifest decryptor.py --uac-admin -F
```

## More information and support for other variants

If you have any difficulties using the decryptor or you came across an extension other than `.mapo` please contact us as at [info@cert.pl](mailto:info@cert.pl).
