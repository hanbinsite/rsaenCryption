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

    public function encryption()
    {
        $publicKey = $this->getPublicKey();
        $publicContent = $this->getContent();
        $key = openssl_pkey_get_public($publicKey);
        if (!$key) {
            return -1;
        }
        $data = pack('H*', $publicContent);
        $content = '';
        $len = 128;
        $pos = 0;
        while ($pos < strlen($data)) {
            $return_res = openssl_public_decrypt(substr($data, $pos, $len), $decrypted, $key);
            if (!$return_res) {
                openssl_free_key($key);
                return 0;
            }
            $content .= $decrypted;
            $pos += $len;
        }
        openssl_free_key($key);
        return $content;
    }
}