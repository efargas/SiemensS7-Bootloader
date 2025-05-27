A=--powersupply-host
B=192.168.0.100
C=--port
D=1238
echo Remaining arguments: "$@"
python3 client.py $A $B $C $D "$@"
