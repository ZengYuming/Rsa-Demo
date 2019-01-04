package com.demo.rsademo.dispatcher;

import com.demo.rsademo.request.SignRequest;
import org.springframework.web.servlet.DispatcherServlet;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * 用于统一对参数的解密
 */
public class SignDispatcher extends DispatcherServlet {
    private static final long serialVersionUID = 1L;

    @Override
    protected void doDispatch(HttpServletRequest request, HttpServletResponse response)
            throws Exception {
        super.doDispatch(new SignRequest(request), response);
    }
}
