import binascii
import optparse

from PIL import Image


def rgb2hex(r, g, b):
    return '#{:02x}{:02x}{:02x}'.format(r, g, b)


def hex2rgb(hexcode):
    return tuple(map(ord, hexcode[1:].decode('hex')))


def str2bin(message):
    binary = bin(int(binascii.hexlify(message), 16))
    return binary[2:]


def bin2str(binary):
    message = binascii.unhexlify('%x' % (int('0b' + binary, 2)))
    return message


def encode(hexcode, digit):
    if hexcode[-1] in ('0', '1', '2', '3', '4', '5'):
        hexcode = hexcode[:-1] + digit
    else:
        return None

    return hexcode


def decode(hexcode):
    if hexcode[-1] in ('0', '1'):
        return hexcode[-1]
    else:
        return None


def hide(file, message):
    img = Image.open(file)
    binary = str2bin(message) + '1111111111111110'
    if img.mode in ('RGBA'):
        img = img.convert('RGBA')
        data = img.getdata()

        prepare_data = []
        digit = 0
        tmp = ''
        for item in data:
            if (digit < len(binary)):
                newpixel = encode(rgb2hex(item[0], item[1], item[2]), binary[digit])
                if newpixel == None:
                    prepare_data.append(item)
                else:
                    r, g, b = hex2rgb(newpixel)
                    prepare_data.append((r, g, b, 255))
                    digit += 1
            else:
                prepare_data.append(item)
        img.putdata(prepare_data)
        img.save(file, "PNG")
        return 'Udalo sie'


def retr(filename):
    img = Image.open(filename)
    binary = ''

    if img.mode in ('RGBA'):
        img = img.convert('RGBA')
        datas = img.getdata()

        for item in datas:
            digit = decode(rgb2hex(item[0], item[1], item[2]))
            if digit == None:
                pass
            else:
                binary = binary + digit
                if (binary[-16:] == '1111111111111110'):
                    print "Sucess"
                    return bin2str(binary[:-16])
        return bin2str(binary)
    return "Incorrect Image Mode"


def Main():
    parser = optparse.OptionParser('usage %prog' + \
                                   '-e/-d <target file>')
    parser.add_option('-e', dest='hide', type='string', \
                      help='target picture path to hide text')
    parser.add_option('-d', dest='retr', type='string', \
                      help='target picture path to retrieve text')

    (options, args) = parser.parse_args()
    if (options.hide != None):
        text = raw_input("Enter a message to hide: ")
        print hide(options.hide, text)
    elif (options.retr != None):
        print retr(options.retr)
    else:
        print parser.usage
        exit(0)


if __name__ == '__main__':
    Main()
