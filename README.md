# README for ID² Client SDK

<br />
IoT设备身份认证ID²（Internet Device ID），是一种物联网设备的可信身份标识，具备不可篡改、不可伪造、全球唯一的安全属性，是实现万物互联、服务流转的关键基础设施。<br />
<br />
ID² Client SDK是用于设备端开发和调试，帮助开发者快速接入ID²开放平台。此SDK, 支持两种载体Demo和SE（Secure Element）：<br />

- Demo载体：用于ID²设备端功能的演示，正式产品，需切换到安全载体（Soft-KM, SE, TEE）。<br />
- SE载体：外挂芯片，ID²预烧录在SE芯片上。<br />

> |—— app：加解密硬件适配（HAL）接口和ID²接口的测试程序。<br />
> |—— doc：相关文档，如ID²指令规范。<br />
> |—— include：头文件目录。<br />
> |—— makefile：总的编译脚本。<br />
> |—— make.rules：编译配置，可配置编译工具链和编译参数。<br />
> |—— make.settings：ID²配置，如调试信息、空发功能和载体选择。<br />
> |—— modules：ID²和ID²依赖的模块。<br />
> |—— sample：示例代码。


<a name="cGT85"></a>
# 快速开始
描述在Ubuntu上编译和运行ID²Client SDK。

<a name="v7uOl"></a>
## 编译环境：
使用Ubuntu 14.04以上版本。

<a name="j7xHp"></a>
## 编译配置：

- make.rules：
>   CROSS_COMPILE： 编译使用的工具链。<br />
>   CFLAGS：编译工具链的编译参数。<br />

- make.settings：
>   CONFIG_ID2_DEBUG：ID²调试信息的开关。<br />
>   CONFIG_ID2_OTP：ID²密钥在使用时动态下发功能的开关。<br />
>   CONFIG_ID2_KM_SE：ID²的SE载体的开关，关闭时，使用Demo载体。<br />
>   CONFIG_ID2_MDU：ID²的模组载体的开关，提供主控ID²SDK, 需使能CONFIG_ID2_MDU宏。<br />


<a name="gG44j"></a>
## 编译SDK：
 在SDK目录，运行如下命令：
>  $ make clean <br />
>  $ make <br />

编译成功，生成的静态库和应用程序统一放在SDK的out目录。

<a name="pPX46"></a>
## 运行程序：
在SDK目录，运行如下命令：
>  ./out/bin/id2_app


测试成功（仅设备端接口测试，非真实交互验证），日志显示如下：
>  <br />
> <LS_LOG> id2_client_get_id 649: ID2: 000FFFFFDB1D8DC78DDCB800 <br />
> <LS_LOG> id2_client_generate_authcode 170: <br />
> ============ ID2 Validation Json Message ============: <br />
> { <br />
>        "reportVersion":        "1.0.0", <br />
>        "sdkVersion":   "2.0.0", <br />
>        "date": "Aug 23 2019 18:17:13", <br />
>        "testContent":  [{ <br />
>                ....... <br />
>                }] <br />
> } <br />
> <LS_LOG> id2_client_generate_authcode 186: =====>ID2 Client Generate AuthCode End. <br />



<a name="MUmQg"></a>
# 其他：
更多文档，如设备端适配和自主验证，请查阅官网文档：
https://help.aliyun.com/product/100846.html?spm=a2c4g.11186623.6.540.928e55380nu9ZO




<br />
