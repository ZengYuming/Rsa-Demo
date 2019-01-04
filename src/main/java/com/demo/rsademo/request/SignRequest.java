package com.demo.rsademo.request;

import com.alibaba.fastjson.JSONObject;
import com.demo.rsademo.util.RSAUtil;
import org.springframework.http.HttpMethod;
import org.springframework.util.StringUtils;

import javax.servlet.*;
import javax.servlet.http.*;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.Principal;
import java.security.PrivateKey;
import java.util.*;


public class SignRequest implements HttpServletRequest {
    public static final String PUBLIC_KEY = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCM/cIpWCKZQfe1VzJv58Yko+de7Rj7FVPhbtzFj9PFkdYtW1mt+S/TFgNwtcSfmiuHu4zjKZTHl1y8Lavt6aUEDhvIMy7HUyT/e26YGNPZ8is3fhoj6BprlB01l01INByIhAKbZTQPTFX95G9jdCIm2YGWaMWDctMzzNr8smRkJwIDAQAB";
    public static final String PRIVATE_KEY = "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAIz9wilYIplB97VXMm/nxiSj517tGPsVU+Fu3MWP08WR1i1bWa35L9MWA3C1xJ+aK4e7jOMplMeXXLwtq+3ppQQOG8gzLsdTJP97bpgY09nyKzd+GiPoGmuUHTWXTUg0HIiEAptlNA9MVf3kb2N0IibZgZZoxYNy0zPM2vyyZGQnAgMBAAECgYBM+6GwgXcix2pBkcLwZ1VBXF1Q75TcQ+DxDl9tYAL5tY+EZISrAYyjbTmjqRwbKUrrafSbdHDQKk1wUl+2IAUBSj4RJ9kZk2kAZdiaXqtmvSu1PHvqhOGxBmwRnXieFY5juPt5BgpG9e//AxWR6z1Nhv9gQOrDp9hI0E5nhD6jgQJBAMROczc/Q19iifeNw090U2Y782g5s0NPxROZlrX11ru9v3hB3cQ012I2aJL1nhrVWIPcMSeyxxyF8xovI5XL1ckCQQC33UaE7v17NcE94EHgZX8Li4zTiUhKDF43gayphi00hJtSYh8Vq4JQokQytYr3UuyjC9i/MQk9F2R2wTJuriJvAkEAussPdT2chTIFqGrbs0o0Za6cMcvd2SoZlEnsj96K4wBuJic+t4m0fT7aiSRwuoXSAT7QAz9pmamYJo0+ZjaciQJAZevSUJROjUMyGMO8oNCCiXrVGNoL6YhLngdTGDIZ0vgDRbrAsnl9ZodcuKNsIkekh4lkoC9liKjz9uSHuVTsHwJACCABQZ2CqEZNr5uZiJOkEzFhErSF0h63avdSZPA+NJZPlqpWSf/AccAK40YY0ZXWri4uHj7qP89gFdd+D2esKw==";

    public HttpServletRequest originalRequest;

    public JSONObject decryptParameterMap;

    public SignRequest() {
    }

    public SignRequest(HttpServletRequest request) {
        originalRequest = request;
        String data="";
        if (request.getMethod().equals(HttpMethod.GET.name())) {
            data = request.getParameter("data");
        }

        if (request.getMethod().equals(HttpMethod.POST.name())) {
            try {
                BufferedReader reader = request.getReader();
                String line = null;
                StringBuffer jb = new StringBuffer();
                while ((line = reader.readLine()) != null) {
                    jb.append(line);
                }
                data =JSONObject.parseObject(jb.toString()).getString("data");
            } catch (Exception ex) {
            }
        }
        if (!StringUtils.isEmpty(data)) {
            PrivateKey privateKey;
            String plaintext;
            try {
                //获取服务端的私钥
                privateKey = RSAUtil.string2PrivateKey(PRIVATE_KEY);
                //用服务端的私钥解密消息
                //eNxHZndBfMPcxY7tSgW9kQCgeTbFu7B5S8ZWu8cI99KBzuLh74iJL7ZrYopW1nyY/kbrPucBJCbiVmbziVeWo/20YKkRbgnRc5Pf8noJMvYcyZ8S/vYT7dd7E3grnDZn2HCkRD1y6zTLoIg+x1QeEgIunvkD/MJs9zQum1WbRmo=
                //eNxHZndBfMPcxY7tSgW9kQCgeTbFu7B5S8ZWu8cI99KBzuLh74iJL7ZrYopW1nyY%2FkbrPucBJCbiVmbziVeWo%2F20YKkRbgnRc5Pf8noJMvYcyZ8S%2FvYT7dd7E3grnDZn2HCkRD1y6zTLoIg%2Bx1QeEgIunvkD%2FMJs9zQum1WbRmo%3D
                plaintext = new String(RSAUtil.privateDecrypt(RSAUtil.base642Byte(data), privateKey));
                System.out.println(plaintext);
                decryptParameterMap = JSONObject.parseObject(plaintext);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    @Override
    public Object getAttribute(String s) {

        return originalRequest.getAttribute(s);

    }

    @Override
    public Enumeration getAttributeNames() {

        return originalRequest.getAttributeNames();

    }

    @Override
    public String getCharacterEncoding() {
        return originalRequest.getCharacterEncoding();
    }

    @Override
    public void setCharacterEncoding(String s)
            throws UnsupportedEncodingException {
        originalRequest.setCharacterEncoding(s);
    }

    @Override
    public int getContentLength() {
        return originalRequest.getContentLength();
    }

    @Override
    public long getContentLengthLong() {
        return originalRequest.getContentLengthLong();
    }

    @Override
    public String getContentType() {
        return originalRequest.getContentType();
    }

    @Override
    public ServletInputStream getInputStream()
            throws IOException {
        return originalRequest.getInputStream();
    }

    @Override
    public String getParameter(String s) {

        // 返回解密后的参数
        return String.valueOf(decryptParameterMap.get(s));
    }

    @Override
    public Enumeration getParameterNames() {
        // 这里是通过实体类注入参数
        return Collections.enumeration(decryptParameterMap.keySet());
    }

    @Override
    public String[] getParameterValues(String s) {

        // 这里是注入参数
        Object o = decryptParameterMap.get(s);
        if (o == null) {
            return null;
        } else {
            return new String[]{String.valueOf(o)};
        }

    }

    @Override
    public Map getParameterMap() {
        return originalRequest.getParameterMap();
    }

    @Override
    public String getProtocol() {
        return originalRequest.getProtocol();
    }

    @Override
    public String getScheme() {
        // TODO Auto-generated method stub
        return originalRequest.getScheme();
    }

    @Override
    public String getServerName() {
        // TODO Auto-generated method stub
        return originalRequest.getServerName();
    }

    @Override
    public int getServerPort() {
        // TODO Auto-generated method stub
        return originalRequest.getServerPort();
    }

    @Override
    public BufferedReader getReader()
            throws IOException {
        // TODO Auto-generated method stub
        return originalRequest.getReader();
    }

    @Override
    public String getRemoteAddr() {
        // TODO Auto-generated method stub
        return originalRequest.getRemoteAddr();
    }

    @Override
    public String getRemoteHost() {

        // TODO Auto-generated method stub
        return originalRequest.getRemoteHost();

    }

    @Override
    public void setAttribute(String s, Object obj) {
        originalRequest.setAttribute(s, obj);
    }

    @Override
    public void removeAttribute(String s) {
        // TODO Auto-generated method stub
        originalRequest.removeAttribute(s);
    }

    @Override
    public Locale getLocale() {

        // TODO Auto-generated method stub
        return originalRequest.getLocale();
    }

    @Override
    public Enumeration<Locale> getLocales() {

        // TODO Auto-generated method stub
        return originalRequest.getLocales();

    }

    @Override
    public boolean isSecure() {

        // TODO Auto-generated method stub
        return originalRequest.isSecure();

    }

    @Override
    public RequestDispatcher getRequestDispatcher(String s) {

        // TODO Auto-generated method stub

        return originalRequest.getRequestDispatcher(s);

    }

    @Override
    public String getRealPath(String s) {

        // TODO Auto-generated method stub
        return originalRequest.getRealPath(s);

    }

    @Override
    public int getRemotePort() {

        // TODO Auto-generated method stub
        return originalRequest.getRemotePort();

    }

    @Override
    public String getLocalName() {

        // TODO Auto-generated method stub
        return originalRequest.getLocalName();

    }

    @Override
    public String getLocalAddr() {

        // TODO Auto-generated method stub
        return originalRequest.getLocalAddr();

    }

    @Override
    public int getLocalPort() {

        // TODO Auto-generated method stub
        return originalRequest.getLocalPort();

    }

    @Override
    public ServletContext getServletContext() {

        // TODO Auto-generated method stub
        return originalRequest.getServletContext();

    }

    @Override
    public AsyncContext startAsync()
            throws IllegalStateException {

        // TODO Auto-generated method stub
        return originalRequest.startAsync();

    }

    @Override
    public AsyncContext startAsync(ServletRequest servletrequest, ServletResponse servletresponse)
            throws IllegalStateException {
        return originalRequest.startAsync(servletrequest, servletresponse);
    }

    @Override
    public boolean isAsyncStarted() {

        return originalRequest.isAsyncStarted();
    }

    @Override
    public boolean isAsyncSupported() {

        return originalRequest.isAsyncSupported();

    }

    @Override
    public AsyncContext getAsyncContext() {

        // TODO Auto-generated method stub
        return originalRequest.getAsyncContext();

    }

    @Override
    public DispatcherType getDispatcherType() {

        // TODO Auto-generated method stub
        return originalRequest.getDispatcherType();

    }

    @Override
    public boolean authenticate(HttpServletResponse httpservletresponse)
            throws IOException, ServletException {

        // TODO Auto-generated method stub
        return originalRequest.authenticate(httpservletresponse);

    }

    @Override
    public String changeSessionId() {

        // TODO Auto-generated method stub
        return originalRequest.changeSessionId();

    }

    @Override
    public String getAuthType() {

        // TODO Auto-generated method stub
        return originalRequest.getAuthType();

    }

    @Override
    public String getContextPath() {

        // TODO Auto-generated method stub
        return originalRequest.getContextPath();

    }

    @Override
    public Cookie[] getCookies() {

        // TODO Auto-generated method stub
        return originalRequest.getCookies();

    }

    @Override
    public long getDateHeader(String s) {

        // TODO Auto-generated method stub
        return originalRequest.getDateHeader(s);

    }

    @Override
    public String getHeader(String s) {

        // TODO Auto-generated method stub
        return originalRequest.getHeader(s);

    }

    @Override
    public Enumeration getHeaderNames() {

        // TODO Auto-generated method stub
        return originalRequest.getHeaderNames();

    }

    @Override
    public Enumeration getHeaders(String s) {

        // TODO Auto-generated method stub
        return originalRequest.getHeaders(s);

    }

    @Override
    public int getIntHeader(String s) {

        // TODO Auto-generated method stub
        return originalRequest.getIntHeader(s);

    }

    @Override
    public String getMethod() {

        return originalRequest.getMethod();
    }

    @Override
    public Part getPart(String s)
            throws IOException, ServletException {

        // TODO Auto-generated method stub
        return originalRequest.getPart(s);

    }

    @Override
    public Collection<Part> getParts()
            throws IOException, ServletException {

        // TODO Auto-generated method stub
        return originalRequest.getParts();

    }

    @Override
    public String getPathInfo() {

        // TODO Auto-generated method stub
        return originalRequest.getPathInfo();

    }

    @Override
    public String getPathTranslated() {

        // TODO Auto-generated method stub
        return originalRequest.getPathTranslated();

    }

    @Override
    public String getQueryString() {

        // TODO Auto-generated method stub
        return originalRequest.getQueryString();

    }

    @Override
    public String getRemoteUser() {

        // TODO Auto-generated method stub
        return originalRequest.getRemoteUser();

    }

    @Override
    public String getRequestURI() {

        // TODO Auto-generated method stub
        return originalRequest.getRequestURI();

    }

    @Override
    public StringBuffer getRequestURL() {

        // TODO Auto-generated method stub
        return originalRequest.getRequestURL();

    }

    @Override
    public String getRequestedSessionId() {

        // TODO Auto-generated method stub
        return originalRequest.getRequestedSessionId();

    }

    @Override
    public String getServletPath() {

        // TODO Auto-generated method stub
        return originalRequest.getServletPath();

    }

    @Override
    public HttpSession getSession() {

        // TODO Auto-generated method stub
        return originalRequest.getSession();

    }

    @Override
    public HttpSession getSession(boolean flag) {

        // TODO Auto-generated method stub
        return originalRequest.getSession(flag);

    }

    @Override
    public Principal getUserPrincipal() {

        // TODO Auto-generated method stub
        return originalRequest.getUserPrincipal();

    }

    @Override
    public boolean isRequestedSessionIdFromCookie() {

        // TODO Auto-generated method stub
        return originalRequest.isRequestedSessionIdFromCookie();

    }

    @Override
    public boolean isRequestedSessionIdFromURL() {

        // TODO Auto-generated method stub
        return originalRequest.isRequestedSessionIdFromURL();

    }

    @Override
    public boolean isRequestedSessionIdFromUrl() {

        // TODO Auto-generated method stub
        return originalRequest.isRequestedSessionIdFromUrl();

    }

    @Override
    public boolean isRequestedSessionIdValid() {

        // TODO Auto-generated method stub
        return originalRequest.isRequestedSessionIdValid();

    }

    @Override
    public boolean isUserInRole(String s) {

        // TODO Auto-generated method stub
        return originalRequest.isUserInRole(s);

    }

    @Override
    public void login(String s, String s1)
            throws ServletException {

        originalRequest.login(s, s1);

    }

    @Override
    public void logout()
            throws ServletException {
        originalRequest.logout();
    }

    @Override
    public <T extends HttpUpgradeHandler> T upgrade(Class<T> class1)
            throws IOException, ServletException {
        return originalRequest.upgrade(class1);
    }
}
