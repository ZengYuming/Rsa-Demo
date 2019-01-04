package com.demo.rsademo.controller;

import com.demo.rsademo.consts.SessionKeyType;
import com.demo.rsademo.util.RSAUtil;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpSession;
import java.net.URLEncoder;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;

/**
 * 模拟客户端
 * 注意：要想正确使用本Controller，需要关掉自定义DispatcherSevelet
 */
@RestController
public class DemoController {
    /**
     * 初始化RSA密钥对
     *
     * @param httpSession
     * @return
     */
    @GetMapping(path = "/initKeyPair")
    public ResponseEntity initKeyPair(HttpSession httpSession) throws Exception {
        //初始化服务端的RSA密
        KeyPair keyPairOfServer = RSAUtil.getKeyPair();
        String publicKeyOfServer = RSAUtil.getPublicKey(keyPairOfServer);
        String privateKeyOfServer = RSAUtil.getPrivateKey(keyPairOfServer);
        httpSession.setAttribute(SessionKeyType.PUBLIC_KEY, publicKeyOfServer);
        httpSession.setAttribute(SessionKeyType.PRIVATE_KEY, privateKeyOfServer);


        Map<String, String> responseBody = new HashMap<>();
        responseBody.put(SessionKeyType.PUBLIC_KEY, publicKeyOfServer);
        responseBody.put(SessionKeyType.PRIVATE_KEY, privateKeyOfServer);
        return new ResponseEntity(responseBody, HttpStatus.OK);
    }

    /**
     * 加密（用公钥加密）
     *
     * @param plaintext   明文文本
     * @param httpSession
     * @return base64编码的文本
     */
    @GetMapping(path = "encrypt")
    public ResponseEntity encrypt(String plaintext, HttpSession httpSession) throws Exception {
        PublicKey publicKey;
        String ciphertext;
        try {
            //获取服务端的公钥
            publicKey = RSAUtil.string2PublicKey((String) httpSession.getAttribute(SessionKeyType.PUBLIC_KEY));
            ciphertext = RSAUtil.byte2Base64(RSAUtil.publicEncrypt(plaintext.getBytes(), publicKey));
        } catch (Exception ex) {
            return new ResponseEntity("Encrypt failed ,message:" + ex.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
        }
        return new ResponseEntity(ciphertext, HttpStatus.OK);
    }

    /**
     * 加密（用公钥加密） 并且UrlEncode编码
     *
     * @param plaintext   明文文本
     * @param httpSession
     * @return URLEncode 之后的文本
     */
    @GetMapping(path = "encryptAndUrlEncode")
    public ResponseEntity encryptAndUrlEncode(String plaintext, HttpSession httpSession) throws Exception {
        ResponseEntity responseEntity = encrypt(plaintext, httpSession);
        return new ResponseEntity(URLEncoder.encode((String) responseEntity.getBody(), "UTF-8"), HttpStatus.OK);
    }

    /**
     * 解密（用私钥解密）
     *
     * @param ciphertext 用公钥加过密的密文（密文需要urlEncode编码：http://tool.chinaz.com/tools/urlencode.aspx）
     * @return 返回解密后的消息文本
     */
    @PostMapping("/message")
    public ResponseEntity receiveMessage(String ciphertext, HttpSession httpSession) throws Exception {
        PrivateKey privateKey;
        String plaintext;
        try {
            //获取服务端的私钥
            privateKey = RSAUtil.string2PrivateKey((String) httpSession.getAttribute(SessionKeyType.PRIVATE_KEY));
            //用服务端的私钥解密消息
            plaintext = new String(RSAUtil.privateDecrypt(RSAUtil.base642Byte(ciphertext), privateKey));
        } catch (Exception ex) {
            return new ResponseEntity("Decrypt failed,message:" + ex.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
        }
        return new ResponseEntity(plaintext, HttpStatus.OK);
    }
}
