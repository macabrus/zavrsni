Upute za pripremu okoline:
```bash
$ python -m venv venv
$ source venv/bin/activate
$ pip install -r requirements.txt
```

Upute za korištenje simulacije (pokretanje 3 instance programa):
```
$ mkdir test/
$ cp -r src/ test/1
$ cp -r src/ test/2
$ cp -r src/ test/3
$ cd test/1/
$ python blockchain.py -k default -p 5000 > 1.log 2>&1 &
$ cd ../..
$ cd test/2/
$ python blockchain.py -k default -p 5001 > 2.log 2>&1 &
$ cd ../..
$ cd test/3/
$ python blockchain.py -k default -p 5002 > 3.log 2>&1 &
$ cd ../..
```

Zatim iz web preglednika možemo pristupiti u tri prozora na localhost:5000, localhost:5001 i localhost:5002.
Upute za korištenje sučelja su detaljno objašnjene u samom radu.


*NAPOMENA: potrebna je python >3.5 verzija.*
