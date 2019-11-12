package cn.jsbintask.securityrestful.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.annotation.Resource;

/**
 * @author jsbintask@foxmail.com
 * @date 2019/1/21 10:33
 */
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Resource
    private TokenExceptionHandler tokenExceptionHandler;
    @Resource
    private AccessDeniedHandler accessDeniedHandler;
    @Resource
    private JwtTokenFilter jwtTokenFilter;
    /**
     * 需要放行的URL
     */
    private static final String[] AUTH_WHITELIST = {
            // -- register url
            "/users/signup",
            "/users/addTask",
            // -- swagger ui
            "/v2/api-docs",
            "/swagger-resources",
            "/swagger-resources/**",
            "/configuration/ui",
            "/configuration/security",
            "/swagger-ui.html",
            "/webjars/**"
            // other public endpoints of your API may be appended to this array
    };
    @Override
    protected void configure(HttpSecurity httpSecurity) throws Exception {
        httpSecurity
                // 因为我们的token是无状态的，不需要跨站保护
                .csrf().disable()
                // 添加异常处理，以及访问禁止（无权限）处理
                .exceptionHandling().authenticationEntryPoint(tokenExceptionHandler).accessDeniedHandler(accessDeniedHandler).and()
                .antMatcher(
                        "/*.html"

                )
              
                // 我们不再需要session了
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()

                //定义拦截页面，所有api全部需要认证


                ;

        //最后，我们定义 filter，用来替换原来的UsernamePasswordAuthenticationFilter
        httpSecurity.addFilterAt(jwtTokenFilter, UsernamePasswordAuthenticationFilter.class);
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring()
                // 让我们获取 token的api不走springsecurity的过滤器，大道开放
                .antMatchers(HttpMethod.GET, "/token","/index", "/login", "/error", "/favicon.ico");
    }
}
