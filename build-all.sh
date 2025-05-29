#!/usr/bin/env bash
#==================================================================
# ██╗  ██╗   ██╗███╗   ██╗██████╗ ██████╗  █████╗
# ██║  ╚██╗ ██╔╝████╗  ██║██╔══██╗██╔══██╗██╔══██╗
# ██║   ╚████╔╝ ██╔██╗ ██║██║  ██║██████╔╝███████║
# ██║    ╚██╔╝  ██║╚██╗██║██║  ██║██╔══██╗██╔══██║
# ███████╗██║   ██║ ╚████║██████╔╝██║  ██║██║  ██║
# ╚══════╝╚═╝   ╚═╝  ╚═══╝╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝
#==================================================================
#
# 文件名称: build-all.sh
# 文件描述: VPS 搭建脚本，包含域名申请，3XUI面板搭建、Sub-Store服务安装、
# 		   Hysteria2 安装、Nginx分流配置。需 root 用户运行。
#		   运行前请自定义修改117-131的端口号。
#
# 作者: Lyndra <lyndra.hyst@gmail.com>
# 版本: 1.0.0
# 创建日期: 2025-04-25
# 最后修改: 2025-05-29
#
# 使用许可: GPLv2 or other licenses
# Copyright (c) 2025 Lyndra
#
#==================================================================

set -eo pipefail

# 颜色配置
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# 命令配置，格式为：[命令名]="描述::处理函数::选项声明1::选项声明2::..."
declare -A COMMAND_MAP=(
	["setup"]="基础环境设置::handle_setup::-u,--user:指定新建用户名（必须）::-p,--pass:指定新建用户密码（必须）::-s,--ssh-port:指定SSH端口（默认：22222）"
	["cert"]="证书管理::handle_cert::-d,--domain:指定主域名（必须，建议优先使用二级域名，可免费开启cloudflare代理保护，三级域名不可免费使用）::-e,--email:指定邮箱（必须）::-t,--token:指定Cloudflare API Token（必须）::-z,--zone-id:指定Cloudflare Zone ID（必须）::-a,--account-id:指定Cloudflare Account ID（必须）"
	["hysteria"]="Hysteria2服务::handle_hysteria::-d,--domain:指定域名（必须，确定证书路径）::-p,--port:指定端口（默认：8443）::-u,--user:指定用户名（必须）::-w,--pass:指定密码（必须）"
	["xui"]="X-UI面板::handle_xui"
	["substore"]="Sub-Store服务::handle_substore::-a,--api-key:指定API密钥（必须）"
	["nginx"]="Nginx分流配置::handle_nginx::-d,--domain:指定域名（必须，确定证书路径）::-x,--xui-domain:指定X-UI域名（必须）::-s,--substore-domain:指定Sub-Store域名（必须）::-p,--port-xui:指定xui访问端口（必须）"
)

# 错误处理函数
panic() {
	echo -e "${RED}[错误]${NC} $1" >&2
	exit 1
}

# 日志输出函数
log_info() {
	echo -e "${GREEN}[信息]${NC} $1" >&2
}

log_warning() {
	echo -e "${YELLOW}[警告]${NC} $1" >&2
}

log_success() {
	echo -e "${GREEN}[成功]${NC} $1" >&2
}

log_debug() {
	echo -e "${BLUE}[调试]${NC} $1" >&2
}

##############################################
#          通用的帮助信息生成函数            #
##############################################

show_command_help() {
	local cmd="$1"
	local info="${COMMAND_MAP[$cmd]}"

	# 1) 把所有 "::" 替换成一个不会在脚本中出现的分隔符，比如 '|'
	info="${info//::/|}"

	# 2) 这时才能安全地用 IFS='|' 来做分割
	local desc handler options_str
	IFS="|" read -r desc handler options_str <<<"$info"

	echo -e "${YELLOW}命令: ${GREEN}$cmd${NC}"
	echo -e "${YELLOW}描述: ${NC}$desc"
	echo -e "${YELLOW}选项:${NC}"

	# 3) 选项声明里可能有多段「::」分隔，继续替换并拆分
	options_str="${options_str//::/|}"
	IFS="|" read -ra opt_lines <<<"$options_str"

	for opt_line in "${opt_lines[@]}"; do
		[[ -z "$opt_line" ]] && continue

		# opt_line 类似 "-p,--package:指定包名（必须）"
		# 用 ":" 分割出（短+长选项）和描述
		IFS=":" read -r flags desc <<<"$opt_line"
		printf "  ${GREEN}%-20s${NC} %s\n" "$flags" "$desc"
	done
}

# 主帮助信息
show_help() {
	echo -e "${YELLOW}使用方法:${NC}"
	echo "  $0 [命令] [选项]"
	echo
	echo -e "${YELLOW}可用命令:${NC}"
	for cmd in "${!COMMAND_MAP[@]}"; do
		local desc=${COMMAND_MAP[$cmd]%%::*}
		printf "  ${GREEN}%-15s${NC} %s\n" "$cmd" "$desc"
	done
	echo -e "\n使用 ${YELLOW}$0 命令 --help${NC} 查看具体命令帮助"
}

##############################################
#               命令处理函数                 #
##############################################


# ==========================================
# 配置信息开始，请根据实际情况修改
# ==========================================

# 新建用户的组id和用户id，默认 1001
groupid=1001
userid=1001

# ssh 登陆端口配置，请确保该端口未被占用
port_ssh=22222

# Hysteria 主端口配置
port_hysteria=8443

# Hysteria 跳跃端口配置
port_hysteria_jump_1=50220
port_hysteria_jump_1_end=50959
port_hysteria_jump_2=60133
port_hysteria_jump_2_end=60968

# ==========================================
# 配置信息结束
# ==========================================


# 基础环境设置
handle_setup() {
	local username=""
	local password=""

	while [[ $# -gt 0 ]]; do
		case $1 in
		-u | --user)
			username="$2"
			shift 2
			;;
		-p | --pass)
			password="$2"
			shift 2
			;;
		-s | --ssh-port)
			port_ssh="$2"
			shift 2
			;;
		-h | --help)
			show_command_help "setup"
			exit 0
			;;
		*)
			panic "未知选项: $1"
			;;
		esac
	done

	[[ -z "$username" ]] && panic "必须指定用户名"
	[[ -z "$password" ]] && panic "必须指定密码"

	log_info "开始设置基础环境..."

	# 安装常用软件
	log_info "安装常用软件..."
	apt update && apt upgrade -y&& apt-get install -y curl vim ufw sudo

	# 创建非root用户
	log_info "创建非root用户: $username"

	getent group ${groupid} || groupadd -g ${groupid} vps
	getent passwd "$username" || useradd -ms /bin/bash -u ${userid} -g ${groupid} -G sudo "$username"
	echo "$username:$password" | chpasswd
	echo "$username ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

	log_info "非root用户创建完成，请在新终端中使用 $username 用户登录，确认是否生效，生效请输入 y/Y，否则请重新运行脚本"
	read -p "请输入y确认：" confirm
	if [ "$confirm" != "y" ] && [ "$confirm" != "Y" ]; then
		panic "非root用户创建完成未生效，请检测系统环境，重新运行脚本"
	fi

	# SSH安全加固
	log_info "配置SSH安全设置..."
	
	# 检查 SSH 端口是否已经修改
	if grep -q "^Port $port_ssh" /etc/ssh/sshd_config; then
		log_info "SSH 端口已设置为 $port_ssh，跳过修改"
	else
		sed -i "s/#Port 22/Port $port_ssh/" /etc/ssh/sshd_config
		sed -i "s/^Port 22/Port $port_ssh/" /etc/ssh/sshd_config
		log_info "SSH 端口已修改为 $port_ssh"
	fi
	
	# 检查 root 登录是否已经禁用
	if grep -q "^PermitRootLogin no" /etc/ssh/sshd_config; then
		log_info "Root 登录已禁用，跳过修改"
	else
		sed -i "s/#PermitRootLogin yes/PermitRootLogin no/" /etc/ssh/sshd_config
		sed -i "s/^PermitRootLogin yes/PermitRootLogin no/" /etc/ssh/sshd_config
		log_info "Root 登录已禁用"
	fi
	
	ufw allow "$port_ssh"
	ufw deny 22

	systemctl restart ssh
	
	log_info "SSH安全设置完成，请在新终端中使用新端口 ssh -p ${port_ssh} ${username}@ip，确认是否生效，生效请输入 y/Y，否则请重新运行脚本"
	read -p "请输入y确认：" confirm
	if [ "$confirm" != "y" ] && [ "$confirm" != "Y" ]; then
		panic "SSH安全设置未生效，请检测系统环境，重新运行脚本"
	fi

	# 防火墙设置
	log_info "配置防火墙..."
	ufw allow 80
	ufw allow 443

	ufw --force enable
	
	log_success "基础环境设置完成"
}

# 证书管理
# 证书管理 - 改进版本
handle_cert() {
	local email=""
	local cf_token=""
	local cf_zone_id=""
	local cf_account_id=""
	local domain=""
	local key_type="ec-256"  # 新增：默认使用 EC-256
	
	while [[ $# -gt 0 ]]; do
		case $1 in
		-d | --domain)
			domain="$2"
			shift 2
			;;
		-e | --email)
			email="$2"
			shift 2
			;;
		-t | --token)
			cf_token="$2"
			shift 2
			;;
		-z | --zone-id)
			cf_zone_id="$2"
			shift 2
			;;
		-a | --account-id)
			cf_account_id="$2"
			shift 2
			;;
		-k | --key-type)
			key_type="$2"
			shift 2
			;;
		-h | --help)
			show_command_help "cert"
			exit 0
			;;
		*)
			panic "未知选项: $1"
			;;
		esac
	done
	
	[[ -z "$domain" ]] && panic "必须指定主域名"
	[[ -z "$email" ]] && panic "必须指定邮箱"
	[[ -z "$cf_token" ]] && panic "必须指定Cloudflare API Token"
	[[ -z "$cf_zone_id" ]] && panic "必须指定Cloudflare Zone ID"
	[[ -z "$cf_account_id" ]] && panic "必须指定Cloudflare Account ID"
	
	# 验证密钥类型
	case "$key_type" in
		"ec-256"|"ec-384"|"2048"|"3072"|"4096")
			;;
		*)
			panic "不支持的密钥类型: $key_type，支持: ec-256, ec-384, 2048, 3072, 4096"
			;;
	esac
	
	log_info "开始申请TLS证书（密钥类型: $key_type）..."
	
	# 安装acme.sh
	log_info "安装acme.sh..."
	curl https://get.acme.sh | sh -s email="$email"
	apt install socat -y
	~/.acme.sh/acme.sh --set-default-ca --server letsencrypt
	source ~/.bashrc
	~/.acme.sh/acme.sh --upgrade --auto-upgrade

	# 设置环境变量
	export CF_Token="$cf_token"
	export CF_Zone_ID="$cf_zone_id"
	export CF_Account_ID="$cf_account_id"
	
	# 申请证书
	local username=$(id -un 1001)

	log_info "申请证书: $domain（密钥类型: $key_type）"
	
	# 检查证书是否已经存在且有效
	if [[ -f "/home/$username/$domain.cer" ]] && [[ -f "/home/$username/$domain.key" ]]; then
		if openssl x509 -in "/home/$username/$domain.cer" -noout -checkend 2592000 > /dev/null 2>&1; then
			log_info "证书已存在且有效期超过30天，跳过申请"
			log_success "证书检查完成"
			return 0
		else
			log_warning "证书已存在但即将过期或无效，重新申请"
		fi
	fi
	
	# 构建 acme.sh 命令
	local acme_cmd="~/.acme.sh/acme.sh --issue --dns dns_cf -d \"$domain\" -d \"*.$domain\""
	
	# 添加密钥长度参数
	acme_cmd="$acme_cmd --keylength $key_type"
	
	# 添加输出文件参数
	acme_cmd="$acme_cmd --key-file /home/$username/$domain.key"
	acme_cmd="$acme_cmd --fullchain-file /home/$username/$domain.cer"
	acme_cmd="$acme_cmd --reloadcmd 'bash -c \"nginx -s reload && x-ui restart\"'"
	
	# 执行命令
	eval $acme_cmd || log_warning "证书申请结果请检查，目前没有安装 nginx，会导致reload失败，但不代表证书申请失败"

	# 修改权限
	log_info "修改证书权限..."
	chmod 644 "/home/$username/$domain.key"
	chmod 644 "/home/$username/$domain.cer"

	# 将证书重命名拷贝，并确保路径正确，主要用于xui设置路径
	mkdir -p "/root/cert/$domain"
	cp "/home/$username/$domain.cer" "/root/cert/$domain/fullchain.pem"
	cp "/home/$username/$domain.key" "/root/cert/$domain/privkey.pem"
	
	# 验证证书
	log_info "验证证书..."
	if openssl x509 -in "/home/$username/$domain.cer" -noout -text > /dev/null 2>&1; then
		log_info "证书文件有效"
		
		# 显示证书信息
		log_info "证书有效期："
		openssl x509 -in "/home/$username/$domain.cer" -noout -dates
		
		log_info "证书包含的域名："
		openssl x509 -in "/home/$username/$domain.cer" -noout -text | grep -A1 "Subject Alternative Name" || echo "  $domain, *.$domain"
	else
		log_warning "证书文件可能有问题，请检查"
	fi
	
	log_success "证书申请完成"
}

# Hysteria2服务
# 逐步在Qos,建议搭建reality
handle_hysteria() {
	local username=""
	local password=""
	local domain=""
	
	while [[ $# -gt 0 ]]; do
		case $1 in
		-d | --domain)
			domain="$2"
			shift 2
			;;
		-p | --port)
			port_hysteria="$2"
			shift 2
			;;
		-u | --user)
			username="$2"
			shift 2
			;;
		-w | --pass)
			password="$2"
			shift 2
			;;
		-h | --help)
			show_command_help "hysteria"
			exit 0
			;;
		*)
			panic "未知选项: $1"
			;;
		esac
	done
	
	[[ -z "$domain" ]] && panic "必须指定主域名"
	[[ -z "$username" ]] && panic "必须指定用户名"
	[[ -z "$password" ]] && panic "必须指定密码"
	
	log_info "开始安装Hysteria2服务..."
	
	# 安装Hysteria2
	log_info "安装Hysteria2..."
	bash <(curl -fsSL https://get.hy2.sh/)
	
	# 配置Hysteria2
	log_info "配置Hysteria2..."

	cat > /etc/hysteria/config.yaml << EOF
listen: :$port_hysteria

tls:
  cert: /home/$(id -un $userid)/$domain.cer
  key: /home/$(id -un $userid)/$domain.key

auth:
  type: userpass
  userpass:
    $username: $password

masquerade:
  type: proxy
  proxy:
    url: https://bing.com
    rewriteHost: true
  listenHTTP: :80
  listenHTTPS: :$port_hysteria

bandwidth:
  up: 20 mbps
  down: 50 mbps
EOF
	
	# 配置端口跳跃
	log_info "配置端口跳跃..."
	ufw allow $port_hysteria_jump_1:$port_hysteria_jump_1_end/udp
	ufw allow $port_hysteria_jump_2:$port_hysteria_jump_2_end/udp
	iptables -t nat -A PREROUTING -i eth0 -p udp --dport $port_hysteria_jump_1:$port_hysteria_jump_1_end -j REDIRECT --to-ports "$port_hysteria"
	iptables -t nat -A PREROUTING -i eth0 -p udp --dport $port_hysteria_jump_2:$port_hysteria_jump_2_end -j REDIRECT --to-ports "$port_hysteria"
	ip6tables -t nat -A PREROUTING -i eth0 -p udp --dport $port_hysteria_jump_1:$port_hysteria_jump_1_end -j REDIRECT --to-ports "$port_hysteria"
	ip6tables -t nat -A PREROUTING -i eth0 -p udp --dport $port_hysteria_jump_2:$port_hysteria_jump_2_end -j REDIRECT --to-ports "$port_hysteria"
	
	ufw allow $port_hysteria

	log_info "启动Hysteria2服务..."
	systemctl enable hysteria-server.service --now
	
	log_success "Hysteria2服务安装完成"
}

# 3X-UI面板
handle_xui() {
	while [[ $# -gt 0 ]]; do
		case $1 in
		-h | --help)
			show_command_help "xui"
			exit 0
			;;
		*)
			panic "未知选项: $1"
			;;
		esac
	done
	
	log_info "开始安装3X-UI面板..."
	
	# 安装X-UI
	log_info "安装3X-UI..."
	bash <(curl -Ls https://raw.githubusercontent.com/MHSanaei/3x-ui/refs/tags/v2.6.0/install.sh)
	
	# 配置X-UI
	log_info "请手动配置3X-UI，或者使用3X-UI备份恢复"
	sleep 2
	x-ui
	log_success "3X-UI面板安装完成，请在 ngninx 反代后，手动完成 ssl 证书路径配置"
}

# Sub-Store服务
handle_substore() {
	local api_key=""
	
	while [[ $# -gt 0 ]]; do
		case $1 in
		-a | --api-key)
			api_key="$2"
			shift 2
			;;
		-h | --help)
			show_command_help "substore"
			exit 0
			;;
		*)
			panic "未知选项: $1"
			;;
		esac
	done
	
	[[ -z "$api_key" ]] && panic "必须指定API密钥"
	
	log_info "开始安装Sub-Store服务..."
	
	# 安装依赖
	log_info "安装依赖..."
	apt update -y && apt install unzip curl wget git -y
	
	# 安装FNM
	log_info "安装FNM..."
	curl -fsSL https://fnm.vercel.app/install | bash
	source ~/.bashrc
	
	# 安装Node
	log_info "安装Node..."
	fnm install v20.18.0
	
	# 安装PNPM
	log_info "安装PNPM..."
	curl -fsSL https://get.pnpm.io/install.sh | sh -
	source ~/.bashrc
	
	# 创建目录
	log_info "创建目录..."
	mkdir -p /root/sub-store
	cd /root/sub-store
	
	# 下载Sub-Store
	log_info "下载Sub-Store..."
	curl -fsSL https://github.com/sub-store-org/Sub-Store/releases/latest/download/sub-store.bundle.js -o sub-store.bundle.js
	curl -fsSL https://github.com/sub-store-org/Sub-Store-Front-End/releases/latest/download/dist.zip -o dist.zip
	unzip -o dist.zip && mv dist frontend && rm dist.zip
	
	# 创建服务
	log_info "创建服务..."
	cat > /etc/systemd/system/sub-store.service << EOF
[Unit]
Description=Sub-Store
After=network-online.target
Wants=network-online.target systemd-networkd-wait-online.service
 
[Service]
LimitNOFILE=32767
Type=simple
Environment="SUB_STORE_FRONTEND_BACKEND_PATH=/$api_key"
Environment="SUB_STORE_BACKEND_CRON=0 0 * * *"
Environment="SUB_STORE_FRONTEND_PATH=/root/sub-store/frontend"
Environment="SUB_STORE_FRONTEND_HOST=0.0.0.0"
Environment="SUB_STORE_FRONTEND_PORT=3001"
Environment="SUB_STORE_DATA_BASE_PATH=/root/sub-store"
Environment="SUB_STORE_BACKEND_API_HOST=127.0.0.1"
Environment="SUB_STORE_BACKEND_API_PORT=3000"
ExecStart=/root/.local/share/fnm/fnm exec --using v20.18.0 node /root/sub-store/sub-store.bundle.js
User=root
Group=root
Restart=on-failure
RestartSec=5s
ExecStartPre=/bin/sh -c ulimit -n 51200
StandardOutput=journal
StandardError=journal
 
[Install]
WantedBy=multi-user.target
EOF
	
	# 启动服务
	log_info "启动服务..."
	systemctl enable sub-store.service --now

	source /root/.bashrc
	log_success "Sub-Store服务安装完成"
}

# Nginx分流配置
handle_nginx() {
	local xui_domain=""
	local substore_domain=""
	local domain=""
	local port_xui=""
	
	while [[ $# -gt 0 ]]; do
		case $1 in
		-d | --domain)
			domain="$2"
			shift 2
			;;
		-x | --xui-domain)
			xui_domain="$2"
			shift 2
			;;
		-s | --substore-domain)
			substore_domain="$2"
			shift 2
			;;
		-p | --port-xui)
			port_xui="$2"
			shift 2
			;;
		-h | --help)
			show_command_help "nginx"
			exit 0
			;;
		*)
			panic "未知选项: $1"
			;;
		esac
	done
	
	[[ -z "$domain" ]] && panic "必须指定主域名"
	[[ -z "$xui_domain" ]] && panic "必须指定X-UI域名"
	[[ -z "$substore_domain" ]] && panic "必须指定Sub-Store域名"
	[[ -z "$port_xui" ]] && panic "必须指定X-UI访问端口"
	
	log_info "开始配置Nginx分流..."
	
	# 安装Nginx
	log_info "安装Nginx..."
	apt install libnginx-mod-stream nginx -y
	
	# 配置Nginx
	log_info "配置Nginx..."
	
	# 修改主配置文件 - 检查是否已经存在 include 语句
	if ! grep -q "include /etc/nginx/vps.conf;" /etc/nginx/nginx.conf; then
		log_info "添加 vps.conf 包含语句到 nginx.conf"
		sudo sed -i '$a\    include /etc/nginx/vps.conf;' /etc/nginx/nginx.conf
	else
		log_info "vps.conf 包含语句已存在，跳过添加"
	fi
	
	# 创建分流配置
	cat > /etc/nginx/vps.conf << EOF
# /etc/nginx/vps.conf

stream {
    # 定义一个映射，将 SNI 中的服务器名映射到后端标识符
    map \$ssl_preread_server_name \$backend {
        hostnames;
        $substore_domain sub;
        $xui_domain xui;
        default hysteria;  # 默认后端
    }

    # 定义各个后端的上游服务器
    upstream sub {
        server 127.0.0.1:8444;  # $substore_domain 对应的后端，对接的是 nginx server
    }

    upstream xui {
        server 127.0.0.1:$port_xui;  # $xui_domain 对应的后端
    }

    upstream hysteria {
        server 127.0.0.1:$port_hysteria;  # 默认后端
    }

    # 定义一个服务器块，监听指定端口并根据 SNI 分发流量
    server {
        listen 443;
        listen [::]:443;
        proxy_pass \${backend};
        ssl_preread on;
    }
}
EOF
	
	# 创建Sub-Store服务器配置
	cat > /etc/nginx/sites-enabled/vps.conf << EOF
server {
    listen 8444 ssl http2;
    listen [::]:8444 ssl http2;
    server_name $substore_domain;
 
    ssl_certificate /home/$(id -un $userid)/$domain.cer;
    ssl_certificate_key /home/$(id -un $userid)/$domain.key;

    location / {
        proxy_pass http://127.0.0.1:3001;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
}
EOF
	
	# 移除默认配置
	rm -f /etc/nginx/sites-enabled/default
	
	# 测试配置
	log_info "测试Nginx配置..."
	nginx -t
	
	# 重启Nginx
	log_info "重启Nginx..."
	systemctl restart nginx
	
	log_success "Nginx分流配置完成"
}

##############################################
#                 主逻辑                     #
##############################################

main() {
	[[ $# -eq 0 ]] || [[ "$1" == "--help" ]] && show_help && exit 0

	local cmd="$1"
	shift

	[[ -n "${COMMAND_MAP[$cmd]}" ]] || panic "未知命令: $cmd"

	# 同样地，这里也要避免直接 IFS="::" 分割
	# 先用 '|' 替换 "::" ，再做一次分割即可
	local info="${COMMAND_MAP[$cmd]}"
	info="${info//::/|}"

	local desc handler options_str
	IFS="|" read -r desc handler options_str <<<"$info"

	# 调用对应的处理函数
	$handler "$@"
}

if [ "$EUID" -ne 0 ]; then
    log_warning "请使用 root 用户运行此脚本" >&2
    exit 1
fi

main "$@"
