# README for ID² Client SDK

IoT Device ID(ID²) is a trusted identity identifier for IoT devices, which can not be tampered with, cannot be forged, and is the only security attribute in the world. It is a key infrastructure for the interconnection of everything and the circulation of services.

ID² Client SDK is used for device-side development and debugging, helping developers to quickly access the ID² open platform. This SDK supports three types of carrier Demo, SE (Secure Element) and MDU (Security Module):

- Demo carrier: used for the demonstration of ID² device-side functions. For the official product, it must be switched to a secure carrier (Soft-KM, SE, TEE).
- SE carrier: external security chip, ID² pre-burned on the SE chip.
- MDU carrier: security module, ID² key and SDK in the module, the main control calls the function of ID² through A&T commands.

> |—— app：Encryption and decryption hardware adaptation (HAL) interface and ID² interface test program.
> |—— doc：Related documents, such as ID² directive specifications.
> |—— include：Header file directory.
> |—— makefile：The total compilation script.
> |—— make.rules：The compilation configuration.
> |—— make.settings：ID² configuration, such as debugging information, idle function and carrier selection.
> |—— modules：ID² and ID² dependent modules.
> |—— sample：Sample code.

# Quick start

Describe to compile and run ID²Client SDK on Ubuntu; for other compiling environments, please refer to makefile to compile and adapt.



## Compiler Environment

Use Ubuntu 14.04 or above.



## Compile configuration

- make.rules：

>  CROSS_COMPILE： The toolchain used for compilation.
>  CFLAGS：The compilation parameters of the compilation tool chain.

- make.settings：

>  CONFIG_LS_ID2_DEBUG：ID² debugging information switch.
>  CONFIG_LS_ID2_OTP：The ID² key is used to dynamically issue the function switch.
>  CONFIG_LS_ID2_ROT_TYPE：The type of ID² security carrier, SE/Demo/MDU.
>  CONFIG_LS_ID2_KEY_TYPE：The key type of ID², 3DES/RSA/AES.



## Compile the SDK:

In the SDK directory, run the following command:

>  $ make clean
>  $ make

The compilation is successful, and the generated static libraries and applications are unified in the out directory of the SDK.



## Run the program:

In the SDK directory, run the following command:

>  ./out/bin/id2_app

The test is successful (only device-side interface test, non-real interaction verification), the log displays as follows:

>
> <LS_LOG> id2_client_get_id 649: ID2: 000FFFFFDB1D8DC78DDCB800
> <LS_LOG> id2_client_generate_authcode 170:
> ============ ID² Validation Json Message ============:
> {
>     "reportVersion":     "1.0.0",
>     "sdkVersion":  "2.0.0",
>     "date": "Aug 23 2019 18:17:13",
>     "testContent":  [{
>         .......
>         }]
> }
> <LS_LOG> id2_client_generate_authcode 186: =====>ID² Client Generate AuthCode End.