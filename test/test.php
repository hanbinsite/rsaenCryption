<?php

require_once '../vendor/autoload.php';

use Rsa\RsaPrivateEncryption;
use Rsa\RsaPrivateDecrypt;

$str = "-----BEGIN PRIVATE KEY-----\nMIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAL8+NF\/+qA0STbcp\nNVkCgqSiyzFGPoON2s\/U2ihmJGzCQSj8s+bpxhgPFz\/J0haOSybg8Oh+TL6LScmy\ntv51mGYJyDsJu\/Ra28h0GQCw81n\/nfa4P5u5L8QIEZV45H3ElhGTKpws85bqnEsI\nsvklq1V5ipObQVTdILk7lZnW5v7XAgMBAAECgYA2j\/7NbJBxukkl+sHXtVmkszWZ\nx1rKmcxWA3qCkDHQPdPtZ7vEI+p6rsOJVYF1If\/bBc515qLqsj7JJw4Cp3ZlGBK1\nBnLtWCR23WUnRpZgUZhJaItNRIS1zovGqVOQKxxl3IWRRso3vdw1pSHneAFIapcY\n8GJVK5DWR8CV7Yl5gQJBAOOOKH7s1Dr5M3q0aKfdwOKuhPhAoB6f+5SJHCnPimmL\nyCDrckbFxAWvtXVeMNqNJVAN8TFO5k6ZJm5BNk0dvncCQQDXJgpr0AgtcS1ANEEg\na0sSr5oLugI0ltDeMa6NkN0jnCsJ+0jyNPagofIxR71zfznwe6CyIzTV6ntFuBfg\n3vqhAkEA2y4xeVf6cDdaS4V8DLy+rlj1AP2WfQkR1RdfxjH+mv0lrfe64cpZrjR5\nbuxj2A798qcLO7hIg0pmxuoPOKY+rwJBAMHx0tcZcyWzrn0AHe1hiw1PKuiDR1Ws\n1qBV3OpUumRNdSbMVRex0tk+45q09v1UpSA58cRjpE9pzrIsn6ngl8ECQEBjX2oW\n54bds\/VN3K2yu\/CG7z2tdWAnGD8WRmhqyezyn6WdGo9qoVtaslEZcy+JZXwUqu0f\nFSQOIXNuIB5dbxk=\n-----END PRIVATE KEY-----\n";

$content = "9746ad30463b16762c2c1de42d9aa2f2377680e82240419d52ae40876d55aef95e93dcc65f8636bf6de773b57e662d330a07942f0674d0b3fbee814c24ee77faed051210504c8510093bab994df9a50450923185ad4b52e04a68dc4c607642dcedb1d91d5d6b8dcafbd6050781ab30c03fafb0c8b5ecc81dac41096ae985c8b36f8ccb719861f16fd745b0f386ea692b08f09df983fb78058c6f582cc0ea7df48b1bcdd91bc0076747cd80fd41ede5f580e34a88e9a3edb42a0d8460ca0e9555e0d2e7cda1edef8133e49e4af2f77a41726eda2567f5da14189823bb6634617a0efc5a7817c2489458fb64b2599e3fcbe425af723986bd6013f77ca2259a4348";

//$class = new RsaPrivateEncryption($content, $str);
$class = new RsaPrivateDecrypt($content, $str);

$result = $class->decrypt();
print_r($class);