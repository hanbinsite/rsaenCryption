# php使用rsa加解密方法

### 更新日志 (最新更新时间2020.08.06)
1. 增加最新方法，去除加密字符串长度限制，原方法有128位长度限制
```
新增方法
$result = $class->encryptionNew(); //加密
$result = $class->decryptNew(); //解密
```

```
私钥解密方法类
use Rsa\RsaPrivateDecrypt 
私钥加密方法
use Rsa\RsaPrivateEncryption 
公钥解密方法
use Rsa\RsaPublicDecrypt 
公钥加密方法
use Rsa\RsaPublicEncryption 
```

```
$class = new RsaPrivateDecrypt('{1}','{2}', '{3}');
{1}:需要加解密内容
{2}:对应公私钥内容
{3}：是否需要将解密完的内容转化为数组，此参数只有解密类有，默认值为false
$result = $class->encryption(); //加密
$result = $class->decrypt(); //解密
```

#### 有什么问题或者建议可以至github评论留言