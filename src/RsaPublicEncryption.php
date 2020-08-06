<?php


/**
 * 公钥加密类
 * Class RsaPublicEncryption
 */

namespace Rsa;

class RsaPublicEncryption
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
     * 加密方法，  此方法有长度限制，128
     * @return false|mixed
     */
    public function encryption()
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

    /**
     * 最新加密方法
     * @return false
     */
    public function encryptionNew()
    {
        $publicKey = $this->getPublicKey();
        $publicContent = $this->getContent();
        $key = openssl_pkey_get_public($publicKey);
        if (!$key) {
            return false;
        }

        $result = openssl_public_encrypt($publicContent, $content, $key);
        openssl_free_key($key);
        if ($result) {
            return $content;
        }
        return false;
    }
}