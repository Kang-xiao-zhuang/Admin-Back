## 登录模块

用户登录 -> 后端验证登录返回 `token` -> 前端带上`token`请求后端数据 -> 后端返回数据， 数据交互流程如下：

![](https://img-blog.csdnimg.cn/direct/f906f0706d75427a959e6486e9897a11.png)

核心实现代码

```java
    @Log("用户登录")
    @ApiOperation("登录授权")
    @AnonymousPostMapping(value = "/login")
    public ResponseEntity<Object> login(@Validated @RequestBody AuthUserDto authUser, HttpServletRequest request) throws Exception {
        // 密码解密
        String password = RsaUtils.decryptByPrivateKey(RsaProperties.privateKey, authUser.getPassword());
        // 查询验证码
        String code = (String) redisUtils.get(authUser.getUuid());
        // 清除验证码
        redisUtils.del(authUser.getUuid());
        // 校验
        if (StringUtils.isBlank(code)) {
            throw new BadRequestException("验证码不存在或已过期");
        }
        if (StringUtils.isBlank(authUser.getCode()) || !authUser.getCode().equalsIgnoreCase(code)) {
            throw new BadRequestException("验证码错误");
        }
        // 获取授权Token
        UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(authUser.getUsername(), password);
        //
        Authentication authentication = authenticationManagerBuilder.getObject().authenticate(authenticationToken);
        SecurityContextHolder.getContext().setAuthentication(authentication);
        
        // 创建token
        String token = tokenProvider.createToken(authentication);
        final JwtUserDto jwtUserDto = (JwtUserDto) authentication.getPrincipal();
        // 返回 token 与 用户信息
        Map<String, Object> authInfo = new HashMap<String, Object>(2) {{
            put("token", properties.getTokenStartWith() + token);
            // jwt用户的信息
            put("user", jwtUserDto);
        }};
        // 判断是否单次登录
        if (loginProperties.isSingleLogin()) {
            // 踢掉之前已经登录的token
            onlineUserService.kickOutForUsername(authUser.getUsername());
        }
        // 保存在线信息
        onlineUserService.save(jwtUserDto, token, request);
        // 返回登录信息
        return ResponseEntity.ok(authInfo);
    }
```

安全框架使用的是 `Spring Security + Jwt Token`， 访问后端接口需在请求头中携带`token`进行访问，请求头格式如下：

```
# Authorization: Bearer 登录时返回的token
Authorization: Bearer eyJhbGciOiJIUzUxMiJ9.eyJqdGkiOiI0OTM3OTRiYmY2MTU0YmNjODk4ODliMjVhY2I2YTZhNyIsInVzZXIiOiJhZG1pbiIsInN1YiI6ImFkbWluIn0.cjp8ESxoyywkzSsmCdFU8SMhPdYlqTvbOPloQTLrxcRKQJUWpRUyaYB1xUnmeXscrlDY1qyRJ6mTJKmBNXiQ
```

## 用户模块

核心查询方法

```java
    @ApiOperation("查询用户")
    @GetMapping
    @PreAuthorize("@el.check('user:list')")
    public ResponseEntity<PageResult<User>> queryUser(UserQueryCriteria criteria, Page<Object> page) {
        if (!ObjectUtils.isEmpty(criteria.getDeptId())) {
            // 集合节点添加
            criteria.getDeptIds().add(criteria.getDeptId());
            // 先查找是否存在子节点
            List<Dept> data = deptService.findByPid(criteria.getDeptId());
            // 然后把子节点的ID都加入到集合中
            criteria.getDeptIds().addAll(deptService.getDeptChildren(data));
        }
        // 数据权限
        List<Long> dataScopes = dataService.getDeptIds(userService.findByName(SecurityUtils.getCurrentUsername()));
        // criteria.getDeptIds() 不为空并且数据权限不为空则取交集
        if (!CollectionUtils.isEmpty(criteria.getDeptIds()) && !CollectionUtils.isEmpty(dataScopes)) {
            // 取交集
            criteria.getDeptIds().retainAll(dataScopes);
            if (!CollectionUtil.isEmpty(criteria.getDeptIds())) {
                return new ResponseEntity<>(userService.queryAll(criteria, page), HttpStatus.OK);
            }
        } else {
            // 否则取并集
            criteria.getDeptIds().addAll(dataScopes);
            return new ResponseEntity<>(userService.queryAll(criteria, page), HttpStatus.OK);
        }
        return new ResponseEntity<>(PageUtil.noData(), HttpStatus.OK);
    }
```

## 异常处理

创建不同的异常，添加`@ExceptionHandler`注解配置发生异常对应的操作

`GlobalExceptionHandler`全局处理异常，

`@RestControllerAdvice`是一个组合注解，适用于所有使用@RequestMapping方法。

这个注解通常用于全局异常的捕获处理和请求参数的增强。

```java
@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler {

    /**
     * 处理所有不可知的异常
     */
    @ExceptionHandler(Throwable.class)
    public ResponseEntity<ApiError> handleException(Throwable e){
        // 打印堆栈信息
        log.error(ThrowableUtil.getStackTrace(e));
        return buildResponseEntity(ApiError.error(e.getMessage()));
    }

    /**
     * BadCredentialsException
     */
    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<ApiError> badCredentialsException(BadCredentialsException e){
        // 打印堆栈信息
        String message = "坏的凭证".equals(e.getMessage()) ? "用户名或密码不正确" : e.getMessage();
        log.error(message);
        return buildResponseEntity(ApiError.error(message));
    }

    /**
     * 处理自定义异常
     */
	@ExceptionHandler(value = BadRequestException.class)
	public ResponseEntity<ApiError> badRequestException(BadRequestException e) {
        // 打印堆栈信息
        log.error(ThrowableUtil.getStackTrace(e));
        return buildResponseEntity(ApiError.error(e.getStatus(),e.getMessage()));
	}

    /**
     * 处理 EntityExist
     */
    @ExceptionHandler(value = EntityExistException.class)
    public ResponseEntity<ApiError> entityExistException(EntityExistException e) {
        // 打印堆栈信息
        log.error(ThrowableUtil.getStackTrace(e));
        return buildResponseEntity(ApiError.error(e.getMessage()));
    }

    /**
     * 处理 EntityNotFound
     */
    @ExceptionHandler(value = EntityNotFoundException.class)
    public ResponseEntity<ApiError> entityNotFoundException(EntityNotFoundException e) {
        // 打印堆栈信息
        log.error(ThrowableUtil.getStackTrace(e));
        return buildResponseEntity(ApiError.error(NOT_FOUND.value(),e.getMessage()));
    }

    /**
     * 处理所有接口数据验证异常
     */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiError> handleMethodArgumentNotValidException(MethodArgumentNotValidException e){
        // 打印堆栈信息
        log.error(ThrowableUtil.getStackTrace(e));
        ObjectError objectError = e.getBindingResult().getAllErrors().get(0);
        String message = objectError.getDefaultMessage();
        if (objectError instanceof FieldError) {
            message = ((FieldError) objectError).getField() + ": " + message;
        }
        return buildResponseEntity(ApiError.error(message));
    }

    /**
     * 统一返回
     */
    private ResponseEntity<ApiError> buildResponseEntity(ApiError apiError) {
        return new ResponseEntity<>(apiError, HttpStatus.valueOf(apiError.getStatus()));
    }
}
```

## 缓存模块

缓存使用的是 `Redis`，默认使用 `Spring` 的注解对系统缓存进行操作

```java
@CacheConfig：主要用于配置该类中会用到的一些共用的缓存配置

@Cacheable：主要方法的返回值将被加入缓存。在查询时，会先从缓存中获取，若不存在才再发起对数据库的访问

@CachePut：主要用于数据新增和修改操作

@CacheEvict：配置于函数上，通常用在删除方法上，用来从缓存中移除相应数据
```

```java
    /**
     * 设置 redis 数据默认过期时间，默认2小时
     * 设置@cacheable 序列化方式
     */
    @Bean
    public RedisCacheConfiguration redisCacheConfiguration() {
        FastJsonRedisSerializer<Object> fastJsonRedisSerializer = new FastJsonRedisSerializer<>(Object.class);
        RedisCacheConfiguration configuration = RedisCacheConfiguration.defaultCacheConfig();
        configuration = configuration.serializeValuesWith(RedisSerializationContext.
                SerializationPair.fromSerializer(fastJsonRedisSerializer)).entryTtl(Duration.ofHours(2));
        return configuration;
    }
```

## 系统日志

系统使用 `AOP` 方式记录用户操作日志，只需要在 `controller` 的方法上使用 `@Log("")` 注解，就可以将用户操作记录到数据库

```java
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface Log {
    String value() default "";
}
```

```java
    /**
     * 配置环绕通知,使用在方法logPointcut()上注册的切入点
     *
     * @param joinPoint join point for advice
     */
    @Around("logPointcut()")
    public Object logAround(ProceedingJoinPoint joinPoint) throws Throwable {
        Object result;
        currentTime.set(System.currentTimeMillis());
        result = joinPoint.proceed();
        SysLog sysLog = new SysLog("INFO", System.currentTimeMillis() - currentTime.get());
        currentTime.remove();
        HttpServletRequest request = RequestHolder.getHttpServletRequest();
        sysLogService.save(getUsername(), StringUtils.getBrowser(request), StringUtils.getIp(request), joinPoint, sysLog);
        return result;
    }

    /**
     * 配置异常通知
     *
     * @param joinPoint join point for advice
     * @param e         exception
     */
    @AfterThrowing(pointcut = "logPointcut()", throwing = "e")
    public void logAfterThrowing(JoinPoint joinPoint, Throwable e) {
        SysLog sysLog = new SysLog("ERROR", System.currentTimeMillis() - currentTime.get());
        currentTime.remove();
        sysLog.setExceptionDetail(new String(ThrowableUtil.getStackTrace(e).getBytes()));
        HttpServletRequest request = RequestHolder.getHttpServletRequest();
        sysLogService.save(getUsername(), StringUtils.getBrowser(request), StringUtils.getIp(request), (ProceedingJoinPoint) joinPoint, sysLog);
    }
```

## AOP模块

接口限流

```java
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface Limit {

    // 资源名称，用于描述接口功能
    String name() default "";

    // 资源 key
    String key() default "";

    // key prefix
    String prefix() default "";

    // 时间的，单位秒
    int period();

    // 限制访问次数
    int count();

    // 限制类型
    LimitType limitType() default LimitType.CUSTOMER;

}
```

核心限流脚本

```java
    /**
     * 限流脚本
     */
    private String buildLuaScript() {
        return "local c" +
                "\nc = redis.call('get',KEYS[1])" +
                "\nif c and tonumber(c) > tonumber(ARGV[1]) then" +
                "\nreturn c;" +
                "\nend" +
                "\nc = redis.call('incr',KEYS[1])" +
                "\nif tonumber(c) == 1 then" +
                "\nredis.call('expire',KEYS[1],ARGV[2])" +
                "\nend" +
                "\nreturn c;";
    }
```

