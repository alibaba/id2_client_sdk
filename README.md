# README for ID² Client SDK

<br />
IoT Device ID(ID²) is a trusted identity identifier for IoT devices, which can not be tampered with, cannot be forged, and is the only security attribute in the world. It is a key infrastructure for the interconnection of everything and the circulation of services. <br />
<br />
ID² Client SDK is used for device-side development and debugging, helping developers to quickly access the ID² open platform. This SDK supports four types of carrier Demo, SE(Secure Element), PUF(Physical Unclonable Function) and MDU(Security Module):<br />

- Demo carrier: used for the demonstration of ID² device-side functions. For the official product, it must be switched to a secure carrier (Soft-KM, SE, TEE). <br />
- SE carrier: external security chip, ID² pre-burned on the SE chip. <br />
- PUF carrier: external security chip, ID² pre-generated in the PUF chip. <br />
- MDU carrier: security module, ID² key and SDK in the module, the main control calls the function of ID² through A&T commands.<br />

> |—— app：Encryption and decryption hardware adaptation (HAL) interface and ID² interface test program. <br />
> |—— doc：Related documents, such as ID² directive specifications. <br />
> |—— include：Header file directory. <br />
> |—— makefile：The total compilation script. <br />
> |—— make.rules：The compilation configuration. <br />
> |—— make.settings：ID² configuration, such as debugging information, idle function and carrier selection. <br />
> |—— modules：ID² and ID² dependent modules. <br />
> |—— sample：Sample code. <br />

# Quick start

Describe to compile and run ID²Client SDK on Ubuntu; for other compiling environments, please refer to makefile to compile and adapt.



## Compiler Environment

Use Ubuntu 14.04 or above.


## Compile configuration

- make.rules：

>  CROSS_COMPILE： The toolchain used for compilation. <br />
>  CFLAGS：The compilation parameters of the compilation tool chain. <br />

- make.settings：

>  CONFIG_LS_ID2_DEBUG：ID² debugging information switch. <br />
>  CONFIG_LS_ID2_OTP：The ID² key is used to dynamically issue the function switch. <br />
>  CONFIG_LS_ID2_ROT_TYPE：The type of ID² security carrier, SE|Demo|MDU|PUF. <br />
>  CONFIG_LS_ID2_KEY_TYPE：The key type of ID², 3DES|AES|RSA|ECC|SM1|SM2|SM4. <br />
>  CONFIG_LS_ID2_ECDP_TYPE: The type of Elliptic Curve Domain Parameter, K-163|K-233|K-283|K-192|K-224|K-256. <br />
>  	- K-163：sect163k1 <br />
> 	- K-233：sect233k1 <br />
> 	- K-283：sect283k1 <br />
> 	- K-192：secp192k1 <br />
>  	- K-224：secp224k1 <br />
> 	- K-256：secp256k1 <br />


## Compile the SDK:

In the SDK directory, run the following command:

>  $ make clean <br />
>  $ make <br />

The compilation is successful, and the generated static libraries and applications are unified in the out directory of the SDK.


## Run the program:

In the SDK directory, run the following command:

>  ./out/bin/id2_app

The test is successful (only device-side interface test, non-real interaction verification), the log displays as follows:

>
> <LS_LOG> id2_client_get_id 649: ID2: 000FFFFFDB1D8DC78DDCB800 <br />
> <LS_LOG> id2_client_generate_authcode 170: <br />
> ============ ID² Validation Json Message ============: <br />
> { <br />
>        "reportVersion":        "1.0.0", <br />
>        "sdkVersion":   "2.0.0", <br />
>        "date": "Aug 23 2019 18:17:13", <br />
>        "testContent":  [{ <br />
>                ....... <br />
>                }] <br />
> } <br />
> <LS_LOG> id2_client_generate_authcode 186: =====>ID2 Client Generate AuthCode End. <br />
