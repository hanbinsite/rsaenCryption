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

    /**
     * 是否需要进行将解密之后的内容转化为数组
     * @var bool
     */
    public $json = false;

    public function __construct($content, $publicKey, $json = false)
    {
        $this->setPublicKey($publicKey);
        $this->setContent($content);
        $this->setJson($json);
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
     * @return bool
     */
    public function getJson()
    {
        return $this->json;
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
     * @param bool $json
     */
    public function setJson($json)
    {
        $this->json = $json;
    }

    /**
     * 解密方法
     * 此方法长度限制为128
     * @return false|mixed
     */
    public function decrypt()
    {
        $publicKey = $this->getPublicKey();
        $publicContent = $this->getContent();
        $json = $this->getJson();
        $key = openssl_pkey_get_public($publicKey);
        if (!$key) {
            return false;
        }
        $data = pack('H*', $publicContent);
        $content = '';
        $len = 128;
        $pos = 0;
        while ($pos < strlen($data)) {
            $return_res = openssl_public_decrypt(substr($data, $pos, $len), $decrypted, $key);
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
     * 使用通用方法进行加密
     * @return false
     */
    public function decryptNew()
    {
        $publicKey = $this->getPublicKey();
        $publicContent = $this->getContent();
        $json = $this->getJson();
        $key = openssl_pkey_get_public($publicKey);
        if (!$key) {
            return false;
        }

        $result = openssl_public_decrypt($publicContent, $content, $key);
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