A=--port
B=1238
C=--method
D=fx3u
E=--powersupply-fx3u-ip
F=192.168.1.18
G=--powersupply-fx3u-port
H=502 
I=--powersupply-fx3u-output
J=Y0
echo Remaining arguments: "$@"
python3 client.py $A $B $C $D $E $F $G $H $I $J "$@"
