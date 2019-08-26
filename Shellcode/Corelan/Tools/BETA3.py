# -*- coding: latin1 -*-
# Copyright (c) 2003-2010, Berend-Jan "SkyLined" Wever <berendjanwever@gmail.com>
# Project homepage: http://code.google.com/p/beta3/
# All rights reserved. See COPYRIGHT.txt for details.
import re, sys;

#_______________________________________________________________________________________________________________________
#                                                                                                                       
#                      ,sSSSs,   ,sSSSs,   : BETA3 - Multi-format shellcode encoding tool.                              
#                     iS"`  XP  YS"  ,SY   :                                                                            
#                    .SP dSS"      ssS"    : Copyright (C) 2003-2010 by SkyLined.                                       
#                    dS'   Xb  SP,  ;SP    : <berendjanwever@gmail.com>                                                 
#                   .SP dSSP'  "YSSSY"     : http://skypher.com/wiki/index.php/BETA3                                    
#__________________ 4S:_________________________________________________________________________________________________
#                                                                                                                       

# http://en.wikipedia.org/wiki/Ascii
# http://en.wikipedia.org/wiki/Code_page_437
# http://en.wikipedia.org/wiki/ISO/IEC_8859-1
numbers                 = "0123456789";
symbols                 = " !\"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~";
symbols_cp437           = "›œž¦§¨©ª«¬­®¯°±²³´µ¶·¸¹º»¼½¾¿ÀÁÂÃÄÅÆÇÈÉÊËÌÍÎÏÐÑÒÓÔÕÖ×ØÙÚÛÜÝÞßìïðñòóôõö÷øùúûüýþÿ";
symbols_latin_1         = " ¡¢£¤¥¦§¨©ª«¬­®¯°±²³´µ¶·¸¹º»¼½¾¿×÷";
uppercase_alpha         = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
uppercase_alpha_cp437   = "€Ž’š¥âãäèêíî";
uppercase_alpha_latin_1 = "ÀÁÂÃÄÅÆÇÈÉÊËÌÍÎÏÐÑÒÓÔÕÖØÙÚÛÜÝÞ";
lowercase_alpha         = "abcdefghijklmnopqrstuvwxyz";
lowercase_alpha_cp437   = "‚ƒ„…†‡ˆ‰Š‹Œ‘“”•–—˜Ÿ ¡¢£¤àáåæçéë";
lowercase_alpha_latin_1 = "ßàáâãäåæçèéêëìíîïðñòóôõöøùúûüýþÿ";
uppercase               = numbers + uppercase_alpha;
uppercase_cp437         = uppercase + uppercase_alpha_cp437;
uppercase_latin_1       = uppercase + uppercase_alpha_latin_1;
lowercase               = numbers + lowercase_alpha;
lowercase_cp437         = lowercase + lowercase_alpha_cp437;
lowercase_latin_1       = lowercase + lowercase_alpha_latin_1;
mixedcase               = numbers + uppercase_alpha + lowercase_alpha;
mixedcase_cp437         = mixedcase + uppercase_alpha_cp437 + lowercase_alpha_cp437;
mixedcase_latin_1       = mixedcase + uppercase_alpha_latin_1 + lowercase_alpha_latin_1;
printable               = mixedcase + symbols;
printable_cp437         = mixedcase_cp437 + symbols + symbols_cp437;
printable_latin_1       = mixedcase_latin_1 + symbols + symbols_latin_1;

minimal_encoding = {
  # http://www.ecma-international.org/publications/files/ECMA-ST/ECMA-262.pdf
  '\x08': r'\b', '\x0C': r'\f', '\x0A': r'\n', '\x0D': r'\r', '\x09': r'\t', 
  '\x0B': r'\v', '\\': r'\\',
}

PIPE_BLOCK_SIZE = 0x1000;

def EncodeNone(format, chars_in_format, seperator, data, badchars, badunichars, switches):
  # format and chars_in_format are ignored here.
  errors = False;
  for i in range(0, len(data)):
    char = data[i];
    errors |= CheckChar(i, char, badchars, switches, char_as_string = "%02X" % ord(char));
  # Return original data if --count is not provided, otherwise return nothing.
  return {True: None, False: data}[switches["--count"]], len(data), errors;

def EncodeAscii(format, chars_in_format, seperator, data, badchars, badunichars, switches):
  result = "";
  errors = False;
  char_codes = [];
  for i in range(0, len(data)):
    char = data[i];
    errors |= CheckChar(i, char, badchars, switches, char_as_string = "%02X" % ord(char));
    char_codes.append(ord(char));
    if len(char_codes) > chars_in_format:
      format_char_codes = char_codes[:chars_in_format];
      del char_codes[:chars_in_format];
      if not switches["--big-endian"]:
        format_char_codes.reverse();
      if result != "":
        result += seperator;
      result += format % tuple(format_char_codes);
  if char_codes:
    while len(char_codes) < chars_in_format:
      char_codes.append(0);
    if not switches["--big-endian"]:
      char_codes.reverse();
    if result != "":
      result += seperator;
    result += format % tuple(char_codes);
  return result, len(data), errors;

def EncodeMinimalAscii(quote, chars_in_format, seperator, data, badchars, badunichars, switches):
  # chars_in_format is ignored here.
  result = "";
  errors = False;
  for i in range(0, len(data)):
    char = data[i];
    if result != "":
      result += seperator;
    if char in minimal_encoding:
      result += minimal_encoding[char];
    elif char == quote:
      result += '\\' + char;
    elif char in printable_latin_1:
      result += char;
    elif (i < len(data) - 1 and data[i+1] not in numbers) \
        or i == len(data) - 1 :
      result += '\\%o' % ord(char);
    else:
      result += '\\x%02X' % ord(char);
    errors |= CheckChar(i, char, badchars, switches, char_as_string = "%02X" % ord(char));
  return result, len(data), errors;

def EncodeUnicode(format, chars_in_format, seperator, data, badchars, badunichars, switches):
  result = "";
  errors = False;
  char_codes = [];
  for i in range(0, len(data), 2):
    char_code = ord(data[i]) + ord(data[i + 1]) * 256;
    errors |= CheckChar(i, unichr(char_code), badunichars, switches, char_as_string = "%04X" % char_code);
    char_codes.append(char_code);
    if len(char_codes) > chars_in_format:
      format_char_codes = char_codes[:chars_in_format];
      del char_codes[:chars_in_format];
      if not switches["--big-endian"]:
        format_char_codes.reverse();
      if result != "":
        result += seperator;
      result += format % tuple(format_char_codes);
  if char_codes:
    while len(char_codes) < chars_in_format:
      char_codes.append(0);
    if not switches["--big-endian"]:
      char_codes.reverse();
    if result != "":
      result += seperator;
    result += format % tuple(char_codes);
  return result, len(data) * 2, errors;

def EncodeMinimalUnicode(quote, chars_in_format, seperator, data, badchars, badunichars, switches):
  # chars_in_format is ignored here.
  result = "";
  errors = False;
  for i in range(0, len(data), 2):
    char_code = ord(data[i]) + ord(data[i + 1]) * 256;
    if char_code < 0x100:
      char = chr(char_code);
      if result != "":
        result += seperator;
      if char in minimal_encoding:
        result += minimal_encoding[char];
      elif char == quote:
        result += '\\' + char;
      elif char in printable_latin_1:
        result += char;
      elif (i < len(data) - 1 and data[i+1] not in numbers) \
          or i == len(data) - 1 :
        result += '\\%o' % ord(char);
      else:
        result += '\\x%02X' % ord(char);
    else:
      char = unichr(char_code);
      result += '\\u%04X' % char_code;
    errors |= CheckChar(i, char, badunichars, switches, char_as_string = "%04X" % char_code);
  return result, len(data), errors;

def CheckChar(i, char, badchars, switches, char_as_string):
  errors = False;
  if char in badchars:
    print >>sys.stderr, "Char %d @0x%02X = bad (%s)" % (i, i, char_as_string);
    errors = True;
  if switches["--nullfree"] and char == '\0':
    print >>sys.stderr, "Char %d @0x%02X = bad (NULL)" % (i, i);
    errors = True;
  if switches["--uppercase"] and char not in uppercase:
    if not switches["--latin-1"] or char not in uppercase_latin_1:
      if not switches["--cp437"] or char not in uppercase_cp437:
        print >>sys.stderr, "Char %d @0x%02X = bad (non-uppercase '%s' %s)" % (i, i, char, char_as_string);
        errors = True;
  if switches["--lowercase"] and char not in lowercase:
    if not switches["--latin-1"] or char not in lowercase_latin_1:
      if not switches["--cp437"] or char not in lowercase_cp437:
        print >>sys.stderr, "Char %d @0x%02X = bad (non-lowercase '%s' %s)" % (i, i, char, char_as_string);
        errors = True;
  if switches["--mixedcase"] and char not in mixedcase:
    if not switches["--latin-1"] or char not in mixedcase_latin_1:
      if not switches["--cp437"] or char not in mixedcase_cp437:
        print >>sys.stderr, "Char %d @0x%02X = bad (non-alphanumeric '%s' %s)" % (i, i, char, char_as_string);
        errors = True;
  if switches["--printable"] and char not in printable:
    if not switches["--latin-1"] or char not in printable_latin_1:
      if not switches["--cp437"] or char not in printable_cp437:
        print >>sys.stderr, "Char %d @0x%02X = bad (non-printable '%s' %s)" % (i, i, char, char_as_string);
        errors = True;
  return errors;

def Decode(decoder_re, decode_base, data, badchars, badunichars, switches):
  result = "";
  errors = False;
  i = 0;
  while i < len(data):
    char_re_match = re.match("^" + decoder_re, data[i:], re.IGNORECASE);
    if not char_re_match:
      print >>sys.stderr, "Char %d @0x%02X does not match encoding: %s." % (i, i, repr(data[i]));
      i += 1;
    else:
      char_encoded_string = char_re_match.group(0);
      char_code_string = char_re_match.group(1);
      try:
        char_code = int(char_code_string, decode_base);
      except ValueError, e:
        print >>sys.stderr, "Char %d @0x%02X has bad character code: %s" % (i, i, e.args[0]);
        errors = True;
      if char_code < 0x100:
        char = chr(char_code);
        errors |= CheckChar(i, char, badchars, switches, char_encoded_string);
      else:
        char = unichr(char_code);
        errors |= CheckChar(i, char, badunichars, switches, char_encoded_string);
      result += char;
      i += len(char_encoded_string);
  return result, len(result), errors;

encodings = {
  "none":  {"enc": EncodeNone,    "fmt": None,           "cpf": 0, "sep": "", "re": None,                 "base": None},
  "h":     {"enc": EncodeAscii,   "fmt": "%02X",         "cpf": 1, "sep": "", "re": r"([0-9A-F]{2})",     "base": 16},
  "hu":    {"enc": EncodeUnicode, "fmt": "%04X",         "cpf": 1, "sep": "", "re": r"([0-9A-F]{4})",     "base": 16},
  "\\'":   {"enc": EncodeMinimalAscii, "fmt": "'",       "cpf": 1, "sep": "", "re": None,                 "base": None},
  "\\\"":  {"enc": EncodeMinimalAscii, "fmt": '"',       "cpf": 1, "sep": "", "re": None,                 "base": None},
  "u\\'":  {"enc": EncodeMinimalUnicode, "fmt": "'",     "cpf": 1, "sep": "", "re": None,                 "base": None},
  "u\\\"": {"enc": EncodeMinimalUnicode, "fmt": '"',     "cpf": 1, "sep": "", "re": None,                 "base": None},
  "\\x":   {"enc": EncodeAscii,   "fmt": "\\x%02X",      "cpf": 1, "sep": "", "re": r"\\x([0-9A-F]{2})",  "base": 16},
  "\\u":   {"enc": EncodeUnicode, "fmt": "\\u%04X",      "cpf": 1, "sep": "", "re": r"\\u([0-9A-F]{4})",  "base": 16},
  "\\u00": {"enc": EncodeAscii,   "fmt": "\\u00%02X",    "cpf": 1, "sep": "", "re": r"\\u00([0-9A-F]{2})", "base": 16},
  "%":     {"enc": EncodeAscii,   "fmt": "%%%02X",       "cpf": 1, "sep": "", "re": r"%([0-9A-F]{2})",    "base": 16},
  "%u":    {"enc": EncodeUnicode, "fmt": "%%u%04X",      "cpf": 1, "sep": "", "re": r"%u([0-9A-F]{4})",   "base": 16},
  "%u00":  {"enc": EncodeAscii,   "fmt": "%%u00%02X",    "cpf": 1, "sep": "", "re": r"%u00([0-9A-F]{2})", "base": 16},
  "&#":    {"enc": EncodeAscii,   "fmt": "&#%d;",        "cpf": 1, "sep": "", "re": r"&#([0-9]{1,3})",    "base": 10},
  "&#u":   {"enc": EncodeUnicode, "fmt": "&#%d;",        "cpf": 1, "sep": "", "re": r"&#([0-9]{1,5})",    "base": 10},
  "&#x":   {"enc": EncodeAscii,   "fmt": "&#x%X;",       "cpf": 1, "sep": "", "re": r"&#x([0-9A-F]{1,2})", "base": 16},
  "&#xu":  {"enc": EncodeUnicode, "fmt": "&#x%X;",       "cpf": 1, "sep": "", "re": r"&#x([0-9A-F]{1,4})", "base": 16},
  "0x8":   {"enc": EncodeAscii,   "fmt": "0x%02X",       "cpf": 1, "sep": ", ", "re": r"0x([0-9A-F]{1,2})", "base": 16},
  "0x16":  {"enc": EncodeAscii,   "fmt": "0x%02X%02X",   "cpf": 2, "sep": ", ", 
                                                                "re": r"0x([0-9A-F]{1,2})([0-9A-F]{1,2})", "base": 16},
  "0x16u": {"enc": EncodeUnicode, "fmt": "0x%04X",       "cpf": 1, "sep": ", ", "re": r"0x([0-9A-F]{1,4})", "base": 16},
  "0x32":  {"enc": EncodeAscii,   "fmt": "0x%02X%02X%02X%02X", "cpf": 4, "sep": ", ", 
                                  "re": r"0x([0-9A-F]{1,2})([0-9A-F]{1,2})([0-9A-F]{1,2})([0-9A-F]{1,2})", "base": 16},
  "0x32u": {"enc": EncodeUnicode, "fmt": "0x%04X%04X",   "cpf": 2, "sep": ", ", "re": 
                                                                      r"0x([0-9A-F]{1,4})([0-9A-F]{1,4})", "base": 16},
};
default_switches = {
    "--nullfree": False, 
    "--lowercase": False, 
    "--uppercase": False,
    "--mixedcase": False,
    "--printable": False,
    "--cp437": False,
    "--latin-1": False,
    "--big-endian": False,
    "--seperator": None,
    "--count": False,
    "--decode": False,
    "--badchars": "",
};

def Help():
  global default_switches;
  print "".center(80, "_");
  print;
  print """    ,sSSSs,   ,sSSSs,  BETA3 - Multi-format shellcode encoding tool.         """.center(80);
  print """   iS"`  XP  YS"  ,SY  (Version 1.2)                                         """.center(80);
  print """  .SP dSS"      ssS"   Copyright (C) 2003-2010 by Berend-Jan "SkyLined" Wever""".center(80);
  print """  dS'   Xb  SP,  ;SP   <berendjanwever@gmail.com>                            """.center(80);
  print """ .SP dSSP'  "YSSSY"    http://skypher.com/wiki/index.php/BETA3               """.center(80);
  print """ 4S:_________________________________________________________________________""".center(80, "_");
  print;
  print "Purpose:";
  print "  BETA can convert raw binary shellcode into text that can be used in exploit";
  print "  source-code. It can convert raw binary data to a large number of encodings.";
  print "  It can also do the reverse: decode encoded data into binary for the same";
  print "  types of encodings.";
  print;
  print "Usage:";
  print "  BETA3.py  [arguments|options]";
  print "";
  print "Arguments:";
  print "  input file path        - Input file with data to be encoded (optional,";
  print "                           default is to read data from stdin)";
  print "  encoding               - One of the following encodings:";
  sorted_encoder_keys = encodings.keys();
  sorted_encoder_keys.sort();
  for name in sorted_encoder_keys:
    if name != "none":
      encoder_enc = encodings[name]["enc"];
      encoder_fmt = encodings[name]["fmt"];
      encoder_cpf = encodings[name]["cpf"];
      encoder_sep = encodings[name]["sep"];
      result = encoder_enc(encoder_fmt, encoder_cpf, encoder_sep, "ABC'\"\r\n\x00", "", "", default_switches);
      print "    %-5s : %s" % (name, result[0]);
    else:
      print "    %-5s : Do not encode or output the input." % name;
  print;
  print "    (All these samples use as input data the string [ABC'\"\\r\\n\\0]. You cannot";
  print "    use some encodings with the \"--decode\" option).";
  print "    The \"--big-endian\" switch has the following effect on the \"0x\" encodings:";
  print;
  for name in sorted_encoder_keys:
    if name != "none" and name.startswith("0x"):
      encoder_enc = encodings[name]["enc"];
      encoder_fmt = encodings[name]["fmt"];
      encoder_cpf = encodings[name]["cpf"];
      encoder_sep = encodings[name]["sep"];
      fake_switches = default_switches.copy();
      fake_switches["--big-endian"] = True;
      result = encoder_enc(encoder_fmt, encoder_cpf, encoder_sep, "ABC'\"\r\n\x00", "", "", fake_switches);
      print "    %-5s : %s" % (name, result[0]);
  print;
  print "Options:";
  print "    --decode             - Decode encoded data to binary.";
  print "                           (By default BETA3 encodes binary data).";
  print "    --count              - Report the number of bytes in the output. When used";
  print "                           with \"none\" encoding, the data is not output, only";
  print "                           the size.";
  print "    --nullfree           - Report any NULL characters in the data.";
  print "    --big-endian         - For \"0x\"-encoding/decoding, select big-endian over";
  print "                           instead of the default little-endian.";
  print "    --seperator=...      - A string of characters to be inserted between values";
  print "    --badchars=XX,XX,... - Report any of the characters supplied by hex value.";
  print "";
  print "    --lowercase, --uppercase, --mixedcase, or --printable";
  print "                         - Report any non-lower-, upper-, or mixedcase";
  print "                           alphanumeric or non-printable characters in the ";
  print "                           data. These options can be combined with both of ";
  print "                           these options:";
  print "    --latin-1            - Allow alphanumeric latin-1 high ascii characters.";
  print "    --cp437              - Allow alphanumeric cp437 high ascii characters.";

def Main():
  global default_switches, encodings;
  switches = default_switches.copy();
  encoding_info = None;
  file_name = None;
  if len(sys.argv) == 1:
    Help();
    return True;
  for i in range(1, len(sys.argv)):
    arg = sys.argv[i];
    if arg in encodings:
      encoding_info = encodings[arg];
    elif arg in switches:
      switches[arg] = True;
    elif arg.find("=") != -1 and arg[:arg.find("=")] in switches:
      switches[arg[:arg.find("=")]] = arg[arg.find("=")+1:];
    elif not file_name:
      file_name = arg;
    else:
      print >>sys.stderr, "Two file names or unknown encoder: '%s' and '%s'" % (file_name, arg);
      Help();
      return False;
  if not encoding_info:
    encoding_info = encodings["none"];
  if not file_name:
    data = sys.stdin.read();
  else:
    data_stream = open(file_name, "rb");
    try:
      data = data_stream.read();
    finally:
      data_stream.close();
  badchars = "";
  badunichars = "";
  if switches is not None and switches["--badchars"] != "":
    for i in switches["--badchars"].split(","):
      char_code = int(i, 16);
      badunichars += unichr(char_code);
      if char_code < 0x100:
        badchars += chr(char_code);
  if not switches["--decode"]:
    if switches["--seperator"] is not None:
      seperator = switches["--seperator"];
    else:
      seperator = encoding_info["sep"];
    encoded_shellcode, byte_count, errors = encoding_info["enc"](encoding_info["fmt"], encoding_info["cpf"], \
        seperator, data, badchars, badunichars, switches);
    if switches["--count"]:
      print "Input: %(i)d (0x%(i)X) bytes, output: %(o)d (0x%(o)X) bytes." % \
          {"i": byte_count, "o": len(encoded_shellcode)};
    if encoded_shellcode is not None:
      sys.stdout.write(encoded_shellcode);
  else:
    decoder_re = encoding_info["re"];
    decoder_base = encoding_info["base"];
    if encoding_info == encodings["none"]:
      print >>sys.stderr, "Cannot decode without an encoding.";
      return False;
    if decoder_re is None:
      print >>sys.stderr, "Cannot decode this type of encoding.";
      return False;
    decoded_shellcode, byte_count, errors = Decode(decoder_re, decoder_base, data, badchars, badunichars, switches);
    if switches["--count"]:
      print "Size: %d (0x%X) bytes." % (byte_count, byte_count);
    if decoded_shellcode is not None:
      sys.stdout.write(decoded_shellcode);
  return not errors;

if __name__ == "__main__":
  success = Main();
  exit_code = {True: 0, False: 1}[success];
  exit(exit_code);