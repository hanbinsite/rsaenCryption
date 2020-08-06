<?php


/**
 * 私钥解密类
 * Class RsaDecrypt
 */

namespace Rsa;

class RsaPrivateDecrypt
{
    /**
     * 私钥加密字符串
     * @var string
     */
    public $privateKey = '';

    /**
     * 需要解密的内容，字符串
     * @var string
     */
    public $content = '';

    public function __construct($content, $privateKey)
    {
        $this->setPrivateKey($privateKey);
        $this->setContent($content);
    }

    /**
     * @return string
     */
    public function getPrivateKey()
    {
        return $this->privateKey;
    }

    /**
     * @return string
     */
    public function getContent()
    {
        return $this->content;
    }

    /**
     * @param string $PrivateKey
     */
    public function setPrivateKey($PrivateKey)
    {
        $this->privateKey = $PrivateKey;
    }

    /**
     * @param string $content
     */
    public function setContent($content)
    {
        $this->content = $content;
    }

    /**
     * 解密方法
     * @return false|string
     */
    public function decrypt()
    {
        $privateKey = $this->getPrivateKey();
        $privateContent = $this->getContent();
        $key = openssl_pkey_get_private($privateKey);
        if (!$key) {
            return false;
        }
        $data = pack('H*', $privateContent);
        $content = '';
        $len = 128;
        $pos = 0;
        while ($pos < strlen($data)) {
            $return_res = openssl_private_decrypt(substr($data, $pos, $len), $decrypted, $key);
            if (!$return_res) {
                openssl_free_key($key);
                return false;
            }
            $content .= $decrypted;
            $pos += $len;
        }
        openssl_free_key($key);
        return $content;
    }
}