<?php

/**
 * 私钥进行加密类
 * Class RsaEncryption
 */

namespace Rsa;

class RsaPrivateEncryption
{
    /**
     * 私钥字符串
     * @var string
     */
    public $privateKey = '';

    /**
     * 需要加密的内容，如果是数组需要进行json_encode
     * @var string
     */
    public $content = '';

    public function __construct($content, $privateKey)
    {
        $this->setPrivateKey($privateKey);
        $this->setContent($content);
    }

    /**
     * @param string $content
     */
    public function setContent($content)
    {
        $this->content = $content;
    }

    /**
     * @return string
     */
    public function getPrivateKey()
    {
        return $this->privateKey;
    }

    /**
     * @param string $privateKey
     */
    public function setPrivateKey($privateKey)
    {
        $this->privateKey = $privateKey;
    }

    /**
     * @return array|string
     */
    public function getContent()
    {
        return $this->content;
    }

    /**
     * 加密方法， 有长度限制，限制为  128
     * @return false|string
     */
    public function encryption()
    {
        $encryptionKey = $this->getPrivateKey();
        $encryptionData = $this->getContent();
        $key = openssl_pkey_get_private($encryptionKey);
        if (!$key) {
            /**
             * 私钥不合法或者私钥初始化失败
             */
            return false;
        }
        $content = '';
        $len = 117;
        $pos = 0;
        while ($pos < strlen($encryptionData)) {
            $return_res = openssl_private_encrypt(substr($encryptionData, $pos, $len), $crypted, $key);
            if (!$return_res) {
                openssl_free_key($key);
                /**
                 * 加密失败
                 */
                return false;
            }
            $content .= $crypted;
            $pos += $len;
        }
        openssl_free_key($key);
        return unpack('H*', $content)[1];
    }

    /**
     * 通用最新加密方法
     * @return false
     */
    public function encryptionNew()
    {
        $encryptionKey = $this->getPrivateKey();
        $encryptionData = $this->getContent();
        $key = openssl_pkey_get_private($encryptionKey);
        if (!$key) {
            /**
             * 私钥不合法或者私钥初始化失败
             */
            return false;
        }
        $result = openssl_private_encrypt($encryptionData, $content, $key);
        openssl_free_key($key);
        if ($result) {
            return $content;
        }
        return false;
    }
}