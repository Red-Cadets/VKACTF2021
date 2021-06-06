##  Судьбоносные записки

| Событие | Название | Категория | Сложность |
| :------ | ---- | ---- | ---- |
| VKA-CTF`2021 |  Судьбоносные записки | квест/Stega | Easy |

### Описание

> Автор: WaffeSoul
>
> Алиса прошлась по просторному кабинету отца, посмотрела на пустующий стол, на котором когда-то стоял папин ноутбук. Она вытащила из стола ящик, начала осматривать его содержимое в поисках чего-то важного, попутно выкладывая вещи наружу. Ящик в конце концов оказался пуст. Алиса замахнулась, чтобы от отчаяния бросить бесполезный контейнер в угол, однако услышала внутри странное дребежание. Ага, двойное дно! А что это у нас там? - Это же папина флешка! Ну что, видимо настало время вспомнить школьные уроки по форенсике?

 

### Решение

Дано USB Flag disk.ad1. Открываем в FTK Imager 4.5. Там находим логи linux и файл pass.txt, в котором логин и пароль. 

>expedition:masterpoint_pass

Далее смотрим логи. Так как в таске говориться о флешки стоит посмотреть логи относительно её. Открываем файл syslog и ищем по названию флешки USB Flag disk
>(7454 строка) May 31 20:27:19 ctf kernel: [ 5023.039688] scsi 33:0:0:0: Direct-Access     Generic  USB Flag Disk   0.00 PQ: 0 ANSI: 6

Далее ищем, где эта флешка была извлечена  из системы
>(7616 строка) May 31 20:29:29 ctf kernel: [ 5153.217259] usb 1-1: USB disconnect, device number 4

В этом диапазоне  ищем не обычные коннекты по лога iptables. Находим:
>(7631 строка) May 31 20:29:11 ctf kernel: [ 5134.808310] IN= OUT=ens33 SRC=192.168.25.130 DST=65.21.151.249 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=62765 DF PROTO=TCP SPT=40948 DPT=4345 WINDOW=64240 RES=0x00 SYN URGP=0 

Переходим по 65.21.151.249:4345 вводим логин и пароль из pass.txt и получаем флаг

**Флаг:**

> vka{l065_fl45h_u5b_p01n7_m4r5_n37}