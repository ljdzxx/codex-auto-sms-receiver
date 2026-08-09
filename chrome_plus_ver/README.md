# `chrome_plus_ver`

Chrome 侧边栏扩展版前端，配合本仓库 Python 后端使用。

## 加载方式

1. 启动后端：`python app.py --host 127.0.0.1 --port 5015`
2. 打开 Chrome 扩展页：`chrome://extensions`
3. 开启“开发者模式”
4. 选择“加载已解压的扩展程序”
5. 选择目录：`chrome_plus_ver`

## 当前实现

- 侧边栏 UI 复用原页面样式和交互
- 扩展前端通过本地后端 API 工作
- 导出文件先由扩展获取，再回传给后端保存到 `data/extension-downloads/`
- 流水线强制串行执行
- 每个任务完成后，扩展会清理当前浏览器环境的缓存、会话存储和 Cookies
- 预留“当前活动页上下文请求”能力，由 `background.js` 的 `run-page-request` 提供
