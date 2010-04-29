
import struct

# se supone que sabemos cuantos headers de streams vamos a tener
number_of_streams = 5

# los bytes leidos
streams = 'l\x00\x00\x00\xfa7\x01\x00#Strings\x00\x00\x00\x00h8\x01\x00\x15o\x00\x00#US\x00\x80\xa7\x01\x00\x94\xb3\x00\x00#Blob\x00\x00\x00\x14[\x02\x00\x10\x00\x00\x00#GUID\x00\x00\x00$[\x02\x00\xecY\x02\x00#~\x00\x00'


for i in range(number_of_streams):
    # el header tiene tamanio fijo, lo leemos
    stream_header = streams[:8]
    offset, size = struct.unpack("I I", stream_header)

    # avanzamos en los bytes leidos
    streams = streams[8:]

    # el largo del string sera hasta el \0, inclusive
    string_len = streams.find('\x00') + 1
    # tenemos que ajustar a ancho fijo de 4 bytes
    padding = (string_len % 4) and (4 - (string_len % 4)) or 0
    # leemos entonces string_len bytes para el string y padding bytes de padding
    fmt = "%ds%dx" % (string_len, padding)
    # la cantidad de bytes que necesitamos para el unpack es la suma
    total_len = string_len + padding
    # podemos unpackear
    string_read = struct.unpack(fmt, streams[:total_len])[0]
    # avanzamos en la cadena de bytes
    streams = streams[total_len:]

    print offset, size
    print string_len, string_read
    