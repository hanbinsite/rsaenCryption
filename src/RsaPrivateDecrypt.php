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

    /**
     * 是否需要进行将解密之后的内容转化为数组
     * @var bool
     */
    public $json = false;

    public function __construct($content, $privateKey, $json = false)
    {
        $this->setPrivateKey($privateKey);
        $this->setContent($content);
        $this->setJson($json);
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
     * @return bool
     */
    public function getJson()
    {
        return $this->json;
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
     * @param bool $json
     */
    public function setJson($json)
    {
        $this->json = $json;
    }

    /**
     * 解密方法,长度限制128
     * @return false|string
     */
    public function decrypt()
    {
        $privateKey = $this->getPrivateKey();
        $privateContent = $this->getContent();
        $json = $this->getJson();
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
        if ($json) {
            parse_str($content, $params);
            return $params;
        }
        return $content;
    }

    /**
     * 通用解密方法，
     * @return false
     */
    public function decryptNew()
    {
        $privateKey = $this->getPrivateKey();
        $privateContent = $this->getContent();
        $json = $this->getJson();
        $key = openssl_pkey_get_private($privateKey);
        if (!$key) {
            return false;
        }

        $result = openssl_private_decrypt($privateContent, $content, $key);
        openssl_free_key($key);
        if ($result) {
            if ($json) {
                parse_str($content, $params);
                return $params;
            }
            return $content;
        }

        return false;
    }
}