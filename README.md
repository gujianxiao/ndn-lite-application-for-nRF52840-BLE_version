# ndn-lite-application-for-nRF52840-BLE_version
This is an applicatione example to show basic function of NDN communication, security sign-on and trust policy switching between the Android phone and development boards using ndn-lite. Specifically, this application consists of two parts: [User application](https://github.com/gujianxiao/NDN-IoT-Android) in the Android phone and ndn-lite application in the development board. The user application is a general Android application that provides UI in terms of available devices, basic devices information and turst policy options etc. The ndn-lite application uses ndn-lite so as to provide NDN based communication, security sign-on and trust policy switching functions etc. Currently this application uses BLE as the face to transmit packets between the Android phone and development boards.
## Requeriments:
    1 or 2 nRF52840 DK
    nRF5 SDK version 15.2.0
    ndn-lite
## Get start:
1) Download or copy the repository into your local directory.  
2) Open the Segger Embedded Project `ndn_lite_nRF52840_example.emProject`. Then, compile and build the project. For the second board, you should copy the content in "main_board2.c" (`$(project Dir)/Application/main_board2.c`) into "main.c", and rebuild the project. 
3) Connect the nRF52840 board with your PC and download the application ("start debugging" or "start without debugging" are both OK) to your board.
4) Make sure you login the user application in the android phone. Then, the board will blink LED 3 to indicate the initiation of the board. The second time blink means the device finish the security sign-on of with the phone.
5) You can press Button 1 to turn on LED 1 and press Button 2 to turn off LED 1. If you have second board, you can press Button 3 to send command Interest to turn on the LED 1 of the second board. If you choose the "Only controller" option on the Android applicatin side, the previous operation will not work.
## Tips:
* Please make sure your [Segger Embedded Studio](https://www.segger.com/products/development-tools/embedded-studio/) is the newest version, or you may cannot build the project corectly.
* You may need to config the path of the "ndn_lite_nRF52840_example" project, do it as follows: 1) open the `ndn_lite_nRF52840_example.emProject` with text edior. 2) Modify all the path of something like `../../nRF5_SDK_15.2.0_9412b96/` to your own path of the directory of your downloaded [nRF5 SDK](https://developer.nordicsemi.com/nRF5_SDK/nRF5_SDK_v15.x.x/).
* When download the project, please make sure you also download `ndn-standalone` library at the same time. If you download the zip file. You may need to go to this [ndn-standalone](https://github.com/Zhiyi-Zhang/ndn_standalone) to download it. If you use git, please remember add "--recursive" option.
