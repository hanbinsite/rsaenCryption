<?php


/**
 * 公钥解密类
 * Class RsaPublicDecrypt
 */

namespace Rsa;

class RsaPublicDecrypt
{

    /**
     * 公钥字符串
     * @var string
     */
    public $publicKey = '';

    /**
     * 需要解密字符串
     * @var string
     */
    public $content = '';

    public function __construct($content, $publicKey)
    {
        $this->setPublicKey($publicKey);
        $this->setContent($content);
    }

    /**
     * @return string
     */
    public function getPublicKey()
    {
        return $this->publicKey;
    }

    /**
     * @return string
     */
    public function getContent()
    {
        return $this->content;
    }

    /**
     * @param string $publicKey
     */
    public function setPublicKey($publicKey)
    {
        $this->publicKey = $publicKey;
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
     * @return false|mixed
     */
    public function decrypt()
    {
        $publicKey = $this->getPublicKey();
        $publicContent = $this->getContent();
        $key = openssl_pkey_get_public($publicKey);
        if (!$key) {
            return false;
        }
        $content = '';
        $len = 117;
        $pos = 0;
        while ($pos < strlen($publicContent)) {
            $return_res = openssl_public_encrypt(substr($publicContent, $pos, $len), $crypted, $key);
            if (!$return_res) {
                openssl_free_key($key);
                return false;
            }
            $content .= $crypted;
            $pos += $len;
        }
        openssl_free_key($key);
        return unpack('H*', $content)[1];
    }
}