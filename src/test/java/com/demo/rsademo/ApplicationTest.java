package com.demo.rsademo;

import com.demo.rsademo.consts.SessionKeyType;
import com.demo.rsademo.util.RSAUtil;
import org.junit.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.net.URLEncoder;
import java.security.PrivateKey;
import java.security.PublicKey;

import static org.junit.Assert.*;

public class ApplicationTest {
    public static final String PUBLIC_KEY = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCM/cIpWCKZQfe1VzJv58Yko+de7Rj7FVPhbtzFj9PFkdYtW1mt+S/TFgNwtcSfmiuHu4zjKZTHl1y8Lavt6aUEDhvIMy7HUyT/e26YGNPZ8is3fhoj6BprlB01l01INByIhAKbZTQPTFX95G9jdCIm2YGWaMWDctMzzNr8smRkJwIDAQAB";
    public static final String PRIVATE_KEY = "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAIz9wilYIplB97VXMm/nxiSj517tGPsVU+Fu3MWP08WR1i1bWa35L9MWA3C1xJ+aK4e7jOMplMeXXLwtq+3ppQQOG8gzLsdTJP97bpgY09nyKzd+GiPoGmuUHTWXTUg0HIiEAptlNA9MVf3kb2N0IibZgZZoxYNy0zPM2vyyZGQnAgMBAAECgYBM+6GwgXcix2pBkcLwZ1VBXF1Q75TcQ+DxDl9tYAL5tY+EZISrAYyjbTmjqRwbKUrrafSbdHDQKk1wUl+2IAUBSj4RJ9kZk2kAZdiaXqtmvSu1PHvqhOGxBmwRnXieFY5juPt5BgpG9e//AxWR6z1Nhv9gQOrDp9hI0E5nhD6jgQJBAMROczc/Q19iifeNw090U2Y782g5s0NPxROZlrX11ru9v3hB3cQ012I2aJL1nhrVWIPcMSeyxxyF8xovI5XL1ckCQQC33UaE7v17NcE94EHgZX8Li4zTiUhKDF43gayphi00hJtSYh8Vq4JQokQytYr3UuyjC9i/MQk9F2R2wTJuriJvAkEAussPdT2chTIFqGrbs0o0Za6cMcvd2SoZlEnsj96K4wBuJic+t4m0fT7aiSRwuoXSAT7QAz9pmamYJo0+ZjaciQJAZevSUJROjUMyGMO8oNCCiXrVGNoL6YhLngdTGDIZ0vgDRbrAsnl9ZodcuKNsIkekh4lkoC9liKjz9uSHuVTsHwJACCABQZ2CqEZNr5uZiJOkEzFhErSF0h63avdSZPA+NJZPlqpWSf/AccAK40YY0ZXWri4uHj7qP89gFdd+D2esKw==";

    /**
     * 加密
     * @throws Exception
     */
    @Test
    public void encrypt() throws Exception {
        String plaintext = "{\"id\":1,\"name\":\"hello world\"}";
        try {
            //获取服务端的公钥
            PublicKey publicKey = RSAUtil.string2PublicKey(PUBLIC_KEY);
            String ciphertext = RSAUtil.byte2Base64(RSAUtil.publicEncrypt(plaintext.getBytes(), publicKey));
            System.out.println(ciphertext);
        } catch (Exception ex) {
            throw ex;
        }
    }

    /**
     * 解密
     * @throws Exception
     */
    @Test
    public void decrypt() throws Exception {
        PrivateKey privateKey;
        String plaintext;
        try {
            //获取服务端的私钥
            privateKey = RSAUtil.string2PrivateKey(PRIVATE_KEY);
            //用服务端的私钥解密消息
            String ciphertext = "jIRf0oaMzz/V16+IlyHaNtO2hK83AX7e7Klm9eSc/lKhTxHvGomKT4xTyiqwqPj62SBsLNwng1d3aSe0/Cnk5htAXfRk9aVvkhlYeAnGz04yXVRUJGwIK5chXMk0BGXDmNnMuExdZlirGs3azTOgPOEn/rPMvK0kMClzPC0tMP4=";
            plaintext = new String(RSAUtil.privateDecrypt(RSAUtil.base642Byte(ciphertext), privateKey));
            System.out.println(plaintext);
        } catch (Exception ex) {
            throw ex;
        }
    }

    /**
     * url 编码
     * @throws Exception
     */
    @Test
    public void URLEncoder() throws Exception {
        String plaintext ="{\"id\":1,\"name\":\"hello world\"}";
        try {
            System.out.println(URLEncoder.encode(plaintext, "UTF-8"));
            //%7B%22id%22%3A1%2C%22name%22%3A%22hello+world%22%7D
        } catch (Exception ex) {
            throw ex;
        }
    }
    /**
     * 加密&URL编码
     * 结果：eNxHZndBfMPcxY7tSgW9kQCgeTbFu7B5S8ZWu8cI99KBzuLh74iJL7ZrYopW1nyY%2FkbrPucBJCbiVmbziVeWo%2F20YKkRbgnRc5Pf8noJMvYcyZ8S%2FvYT7dd7E3grnDZn2HCkRD1y6zTLoIg%2Bx1QeEgIunvkD%2FMJs9zQum1WbRmo%3D
     * @throws Exception
     */
    @Test
    public void encryptAndURLEncoder() throws Exception {
        String plaintext = "{\"id\":1,\"name\":\"hello world\"}";
        try {
            //获取服务端的公钥
            PublicKey publicKey = RSAUtil.string2PublicKey(PUBLIC_KEY);
            String ciphertext = RSAUtil.byte2Base64(RSAUtil.publicEncrypt(plaintext.getBytes(), publicKey));
             System.out.println(URLEncoder.encode(ciphertext, "UTF-8"));
        } catch (Exception ex) {
            throw ex;
        }
    }
}