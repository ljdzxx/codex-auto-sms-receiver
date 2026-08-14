在插件界面的'账号与任务-导入已有帐号'模块，新增一种新的'登录素材类型'：smsbower-gmail，此类型通过smsbower-email-API接口获取邮箱和验证码，界面取消'账号素材'多行文本输入框，取而代之的是提供以下两个API参数的配置项(持久化)：

----
$api_key - Your API Key

$maxPrice - max price for mail

$codeTimeout - 验证码超时(默认120s)

$codeInterval - 验证码刷新频率(默认5s)

-----

# smsbower-email-API接口文档

## Get mail
https://smsbower.page/api/mail/getActivation?api_key=scnsd1H4t5gl5fbiJUmNlBztY*******&service=$SERVICE&domain=$DOMAIN&ref=$ref&alias=$alias

Parameters
$api_key - Your API Key
$service - 'dr'
$domain - 'gmail.com'
$maxPrice - max price for mail
$ref - transfer the referral ID
$alias - return mail as alias (1/0)

Required:
$api_key
$service

Example of an answer JSON
```json
{"status":1"mail":"exmaple@gmail.com","mailId":4,}
```

Example of an error JSON
```json
{
      "status": 0
      "error": "No mails yet",
}
```

## Get mail code
https://smsbower.page/api/mail/getCode?api_key=scnsd1H4t5gl5fbiJUmNlBztY*******&mailId=$mailId

Parameters
$api_key - Your API Key
$mailId - Mail activation ID received in response to mail request

Required:
$api_key
$mailId

Example of an answer JSON
```json
{"status":1"code":"code",}
```

Example of an error JSON
```json
{
      "status": 0
      "error": "Pass mail id",
}
```
Possible mistakes
Pass mail id - The mailId parameter is invalid or was not sent at all
Activation is already canceled - Your activation is canceled
Code has not been received yet, please try again later - Your verification code is not received now


## Change activation status
https://smsbower.page/api/mail/setStatus?api_key=scnsd1H4t5gl5fbiJUmNlBztY*******&id=MAIL_ACTIVATION_ID&status=STATUS

Parameters
$api_key - Your API Key
$id - Mail activation id (2 - Cancel, 5 - For waiting next code, 3 - To successfully close activation after code received and write off money from reserved balance)
Required:
$api_key
$id

Example of an answer JSON
```json
{"status":1"message":Success}
```

Possible mistakes
Bad actual activation status - Bad actual activation status
No activation found with such id - No activation found with such id


# 登录素材'smsbower-gmail'的处理流程：

1、chatgpt登录页输入邮箱

2、输入邮箱后，判断页面是否导向https://auth.openai.com/email-verification(页面快照：logs/debug/1038377801-20260811-032917-screenshot.log)?如果导向的是其他页面，则本次流程终止(调用API-Change activation status，设置 status=2 Cancel本次账号[失败无需处理])，开始处理下一个账号

3、点击/email-verification页面底部的'Continue with password'按钮设置密码登录模式，页面将导向：https://auth.openai.com/create-account/password(页面快照：logs/debug/1038377801-20260811-033148-screenshot.log)

4、随机生成12位ChatGPT密码(仅包含大小写字母、数字)设置后继续下一步(注意保存生成的密码，并与当前帐号关联，后续将跟随账号导出);

5、此时页面重新导向：https://auth.openai.com/email-verification，进入等待验证码阶段，你开始从上述接码API不断的刷新(频率:$codeInterval)查询验证码，如果未获取到则持续等待，直至$codeTimeout超时本次流程终止(同上调用API Cancel 本次账号)，有值则尝试输入进行验证（此时如果页面报错'Incorrect code'[快照:logs/debug/1038377833-20260811-080724-screenshot.log]则继续等待$codeTimeout，并仍保持$codeInterval的刷新频率继续接码，直至第2次$codeTimeout超时仍收不到新的验证码则放弃本次的账号[调用API-Change activation status，设置 status=2 Cancel本次账号]，继续下一个账号的处理）

6、验证成功，页面可能会进入：https://auth.openai.com/about-you(页面快照：logs/debug/1038377801-20260811-033912-screenshot.log)，则开始生成随机的姓名与年龄(20-55)并填入，并点击'Finish creating account'按钮保存，等待页面URL发生变化，进入https://chatgpt.com/*，随后调用API-Change activation status，设置 status=3 完成本次账号[失败无需处理]


## 注册成功后继续设置 Multi-factor authentication (MFA)
7、将浏览器URL导向：https://chatgpt.com/#settings/Security(页面快照:logs/debug/1038377795-20260811-030356-screenshot.log)，点击弹窗中的'Security and login'主菜单，在随后展示出的右侧界面中点击开启'Authenticator app'
此时可能遇到挑战，需要再次输入邮件验证码：页面跳转到邮件验证码页面https://auth.openai.com/email-verification(快照：debug/1038377810-20260811-052123-screenshot.log)，此时点击底部'Continue with password'按钮跳过验证码使用密码验证：https://auth.openai.com/log-in/password(页面快照：logs/debug/1038377801-20260811-034933-screenshot.log)，输入你刚才生成的12位密码进行验证;

8、无论是否遇到验证码挑战，页面最终会回到https://chatgpt.com/#settings/Security，弹出MFA设置界面(页面快照：logs/debug/1038377801-20260811-035106-screenshot.log)，点击其中的'Trouble scanning?'将展示MFA的base64密钥字符串(页面快照：logs/debug/1038377801-20260811-035428-screenshot.log)，获取并记下这串密钥，并与当前账户关联，后续将跟随账号导出

9、随后利用已有的MFA/2FA生成验证码算法算出6位验证码并填入（注意有效时间，如果小于3秒则继续等待下一轮验证码）

10、至此，成功获取'smsbower-gmail'类型登录素材，将它转换成name@example.com----ChatGPT密码----Base32密钥格式的素材，展示在'账号清单'中

# '账号清单'增加'导出账号'功能:

'账号清单'中增加一个'导出账号'的按钮，按导入的素材类型原样导出('smsbower-gmail'素材处理成功后已自动转换成了name@example.com----ChatGPT密码----Base32密钥格式的素材，按此格式导出)



补充：
1038377833那份快照没有'Continue with password'很正常，因为那个界面已经是点了'Continue with password'按钮之后的页面，如果还有才不正常！