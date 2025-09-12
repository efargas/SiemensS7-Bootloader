from pymodbus.datastore import ModbusServerContext, ModbusSequentialDataBlock, ModbusDeviceContext
from pymodbus.server import StartTcpServer

store = ModbusDeviceContext(
    di=ModbusSequentialDataBlock(0, [0]*100),
    co=ModbusSequentialDataBlock(0, [0]*100),
    hr=ModbusSequentialDataBlock(0, [0]*100),
    ir=ModbusSequentialDataBlock(0, [0]*100),
)
devices = {i: store for i in range(0, 256)}
context = ModbusServerContext(devices=devices, single=False)
StartTcpServer(context, address=("0.0.0.0", 1502))
