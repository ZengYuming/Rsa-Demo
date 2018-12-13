RSA加解密demo
======
RSA实现过程参考：https://blog.csdn.net/hustpzb/article/details/72734578   
RSA原理参考： https://blog.csdn.net/qq_31805821/article/details/80579797

最终实现，需要要避免的坑：
1.密钥中的\r\n换行符要去掉，否则直接用来加解密，会报超出长度。可以用org.springframework.util.Base64Utils工具类来做base64和byte的转换，就不会有\r\n换行符出现了
2.byte[] 转 String，不要直接.toString(),toString()返回的是内存地址，不是字符串。可以用new String(byte[])来代替
3.密文传给服务器解密的时候，要用urlEncode就行编码，不然http请求失败


问：为什么不做一个简单的单元测试来做demo？而是写一个完整的RestfulApi
答：因为完整的RestfulApi更接近真是场景，演示真是的请求


C:\Users\tony\Downloads\RsaDemo-master

