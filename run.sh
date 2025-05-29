#!/bin/bash

#==================================================================
# ██╗  ██╗   ██╗███╗   ██╗██████╗ ██████╗  █████╗
# ██║  ╚██╗ ██╔╝████╗  ██║██╔══██╗██╔══██╗██╔══██╗
# ██║   ╚████╔╝ ██╔██╗ ██║██║  ██║██████╔╝███████║
# ██║    ╚██╔╝  ██║╚██╗██║██║  ██║██╔══██╗██╔══██║
# ███████╗██║   ██║ ╚████║██████╔╝██║  ██║██║  ██║
# ╚══════╝╚═╝   ╚═╝  ╚═══╝╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝
#==================================================================
#
# 文件名称: run.sh
# 文件描述: VPS构建脚本
# 运行环境：Debian 系 Linux 系统，Root 用户运行。
# 注意事项：
#   1. 运行前，请运行 build-all.sh --help 查看脚本中的命令含义，以及每个指令的参数含义。
#   2. 尽可能的先修改 build-all.sh 中的配置端口，保证安全（119-141行）。
#   3. 通过Cloudflare申请DNS时，需要确认Cloudflare的api令牌，是否允许了新 vps 的ipv4和ipv6地址。
#   4. 尽可能的使用二级域名，CF的代理功能中，二级域名边缘证书是免费的，但三级域名需要开会员才能用。三级域名签发证书，同时使用代理功能，会导致SSL握手失败。
#   5. XUI提供备份和恢复功能，但是需要注意其SSL证书路径也会被备份，如果新旧机器的证书不一致，将导致无法网页访问，此时需要命令行修改XUI的SSL证书路径。本脚本会自动复制证书到xui的证书路径。
#   6. 对于 xui 上启用的各种协议所需要的端口请手动放行防火墙。
#   7. sub-store 建议开启github的glist备份，网上有很多教程，很简单。新机器可以直接完美同步。
# 作者: Lyndra <lyndra.hyst@gmail.com>
# 版本: 1.0.0
# 创建日期: 2025-05-29
# 最后修改: 2025-05-29
# 使用许可: GPLv2 or other licenses
# Copyright (c) 2025 Lyndra
#
#==================================================================

echo "运行前请先修改 *build-all.sh* 和 *本脚本* 中的配置信息，确保配置信息正确。"

echo "输入 y/Y 确认上述操作已完成，输入 n/N 退出"
read -p "请输入: " confirm

if [ "$confirm" != "y" ] && [ "$confirm" != "Y" ]; then
    echo "退出脚本"
    exit 0
fi

# 创建新用户，请根据实际情况修改用户名和密码
# 密码需要足够复杂，否则创建用户时会失败。
./build-all.sh setup -u username -p password

# 申请证书，请根据实际情况修改域名、邮箱、cloudflare的api令牌、cloudflare zone id、cloudflare account id。
# 请确认cloudflare的api令牌，是否允许了新 vps 的ipv4和ipv6地址。
./build-all.sh cert -d 二级域名 -e 邮箱 -t api_token -z zone_id -a account_id

# 安装 hysteria2，请根据实际情况修改域名、用户名、密码。
./build-all.sh hysteria -d 二级域名 -u 用户名 -w 密码

# 安装 xui，安装过程中请自行配置xui，并记录xui的访问端口
./build-all.sh xui

# 安装 sub-store，请修改token，否则可能会被盗取后端信息。
./build-all.sh substore -a custom_token

./build-all.sh nginx -d 二级域名 -x xui-域名 -s sub-store-域名 -p x-ui-访问端口

