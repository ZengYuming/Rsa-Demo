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
===================全局统一解密，并且无感注入action参数========================
1.启动类里面声明：SignDispatcher
2.需要的自定义类：SignDispatcher & SignRequest
======================DemoController实验===========================
1.1.初始化客户端&服务端的RSA密钥对 http://localhost:8080/initKeyPair
2.加密（用服务端的公钥进行加密）    （可以跳过）
3.加密（用公钥加密） 并且UrlEncode编码  http://localhost:8080/encryptAndUrlEncode?plaintext=hello world
4.接收客户端发来的密文消息（密文记得要url编码）http://localhost:8080/message?ciphertext=YPvwXaE%2FhNOln%2Br3%2BZHu3YdLvwSDGEtpEyJ7slha8o0iBx7u4jHIjtR7uNRN%2BmDqKcMs0hnYsFRQ%2F%2F0O4aFOpNQpbSub7HMzb7D%2BIzx4d0w1rovTWMO%2Bv1aEJw%2BX6qN9dKBIqHkopn6hssBVKzVGoaWz60FUHh8d7uDZurnoYQ0%3D

======================APIController实验========================
参数data:需要进行加密&URL编码（可以用单元测试类ApplicationTest的encryptAndURLEncoder方法进行加密&URL编码）
1.Get 请求实验(data参数需要URL编码)： http://localhost:8080/api?data=eNxHZndBfMPcxY7tSgW9kQCgeTbFu7B5S8ZWu8cI99KBzuLh74iJL7ZrYopW1nyY%2FkbrPucBJCbiVmbziVeWo%2F20YKkRbgnRc5Pf8noJMvYcyZ8S%2FvYT7dd7E3grnDZn2HCkRD1y6zTLoIg%2Bx1QeEgIunvkD%2FMJs9zQum1WbRmo%3D
2.POST测试 （不需要url编码）http://localhost:8080/api     body:{"data":"eNxHZndBfMPcxY7tSgW9kQCgeTbFu7B5S8ZWu8cI99KBzuLh74iJL7ZrYopW1nyY/kbrPucBJCbiVmbziVeWo/20YKkRbgnRc5Pf8noJMvYcyZ8S/vYT7dd7E3grnDZn2HCkRD1y6zTLoIg+x1QeEgIunvkD/MJs9zQum1WbRmo="}  

