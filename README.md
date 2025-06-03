# 自建 VPS 代理脚本

本脚本用于自建 reality、hysteria 节点，提供安全的节点搭建方式，通过修改 ssh 端口、ngnix 分流等方式，降低服务器对外暴露服务的风险，提升 vps 安全性。

同时依靠 3xui 面板搭建节点，能够为少数人提供服务，便于管理。建议只想其他用户提供 reality 节点，更加稳定可靠，hysteria 目前在逐渐被管控，高峰期会出现断流等问题。

更加详细的内容请参考：[年轻人的第一台-vps-代理服务器](https://www.hysling.top/blog/proxy/%E5%B9%B4%E8%BD%BB%E4%BA%BA%E7%9A%84%E7%AC%AC%E4%B8%80%E5%8F%B0-vps-%E4%BB%A3%E7%90%86%E6%9C%8D%E5%8A%A1%E5%99%A8/)

本脚本采用模块化设计，build-all.sh 脚本将各个搭建功能模块化，通过 run.sh 脚本统一调用，建议先阅读上述博客，再来看 run.sh 的内容。通过本脚本，可以方便的搭建服务，但搭建过程中，仍然需要额外操作，比如在 cloudflare 中设置域名 dns，创建 api 令牌，购买域名等。

本脚本更像是在上述博客的操作简化版，原理和步骤和博客一致，但节省大量时间。

使用方式：修改 run.sh 中相关的配置信息，以及 build-all.sh 中的端口，然后命令行执行 ./run.sh 即可。

脚本可查看具体帮助信息。

```bash
$ ./build-all.sh --help
使用方法:
  ./build-all.sh [命令] [选项]

可用命令:
  xui             X-UI面板
  nginx           Nginx分流配置
  setup           基础环境设置
  cert            证书管理
  substore        Sub-Store服务
  hysteria        Hysteria2服务

使用 ./build-all.sh 命令 --help 查看具体命令帮助
```
