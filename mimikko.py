# -*- coding: UTF-8 -*-
"""
 * @author  cyb233
 * @date  2021/1/9
"""
import argparse
import base64
import hashlib
import hmac
import json
import logging
import re
import sys
import time
#import urllib.parse
import random
import requests
import os.path
from urllib3.exceptions import InsecureRequestWarning

import push

requests.urllib3.disable_warnings(InsecureRequestWarning)

with open('configs/options.json', 'r') as e:
    options = json.load(e)

def main():
    LOG_FORMAT = "%(asctime)s - %(levelname)s - %(filename)s:%(lineno)s - %(funcName)s - %(message)s"
    DATE_FORMAT = "%Y/%m/%d %H:%M:%S %p"
    logging.basicConfig(level=logging.INFO, format=LOG_FORMAT, datefmt=DATE_FORMAT)
    print()
    logging.debug('DEBUG 开启')

    try:
        parser = argparse.ArgumentParser(
            description='请从 登录账号(-u)和密码(-p) 或 AUTHORIZATION验证(-a) 中选择一种登录方式')

        parser.add_argument('-u', default=False, metavar='ID', help='登录账号(邮箱或手机号)')
        parser.add_argument('-p', default=False, metavar='password', help='登录密码')
        parser.add_argument('-a', default=False, metavar='Token',
                            help='AUTHORIZATION验证，抓包获取')
        parser.add_argument('-e', default=False, metavar='code', help='助手代码，选择助手')
        parser.add_argument('-r', default=False,
                            metavar='resign', help='补签最近x天，可选数字1~7')
        parser.add_argument('-s', default=False,
                            metavar='SCKEY', help='server酱推送密钥')
        parser.add_argument('-d', default=False,
                            metavar='token', help='钉钉机器人token')
        parser.add_argument('-c', default=False,
                            metavar='secret', help='钉钉机器人安全设置加签的secret')
        parser.add_argument('-i', default=False,
                            metavar='CompanyId', help='企业微信推送CompanyId')
        parser.add_argument('-x', default=False,
                            metavar='Secret', help='企业微信推送Secret')
        parser.add_argument('-w', default=False,
                            metavar='AgentId', help='企业微信推送AgentId')
        parser.add_argument('-b', default=False,
                            metavar='dcWebhook', help='Discord推送WebHook')
        parser.add_argument('-t', default=False,
                            metavar='tgtoken', help='Telegram Bot Token')
        parser.add_argument('-g', default=False,
                            metavar='tgid', help='你的Telegram id')
        parser.add_argument('-k', default=False,
                            metavar='pptoken', help='PushPlus推送Token')
        parser.add_argument('-f', default=False,
                            metavar='fstoken', help='飞书机器人token')
        parser.add_argument('-j', default=False,
                            metavar='fssecret', help='飞书机器人安全设置加签的secret')
        parser.add_argument('-l', default=False,
                            metavar='misaka20001position', help="MisakaNet服务器地址")
        parser.add_argument('-m', default=False,
                            metavar="misakakey", help="MisakaNet misakaKey")

        args = parser.parse_args()

        # 如果不带参数启动
        if len(sys.argv) < 2:
            if(os.path.isfile("configs/account.json")):
                logging.info('未指定任何参数，尝试从 configs/account.json 读取配置参数......')
                with open('configs/account.json', 'r') as f:
                    config = json.load(f)
            else:
                logging.info('未找到 configs/account.json 配置文件')
                parser.print_help()
                sys.exit(0)
        logging.info('正在获取secret参数')
        if(os.path.isfile("configs/account.json")):
            user_id = config["ID"]
            user_password = config["Password"]
            Authorization = config["Authorization"]
            Energy_code = config["Energy_code"]
            resign = config["resign"]
            SCKEY = config["SCKEY"]
            DDTOKEN = config["DDTOKEN"]
            DDSECRET = config["DDSECRET"]
            wxAgentId = config["wxAgentId"]
            wxSecret = config["wxSecret"]
            wxCompanyId = config["wxCompanyId"]
            dcwebhook = config["dcwebhook"]
            tgtoken = config["tgtoken"]
            tgid = config["tgid"]
            pptoken = config["pptoken"]
            fstoken = config["fstoken"]
            fssecret = config["fssecret"]
            misaka20001position = config["misaka20001position"]
            misakaKey = config["misakaKey"]
        else:
            user_id = args.u
            user_password = args.p
            Authorization = args.a
            Energy_code = args.e
            resign = args.r
            SCKEY = args.s
            DDTOKEN = args.d
            DDSECRET = args.c
            wxAgentId = args.w
            wxSecret = args.x
            wxCompanyId = args.i
            dcwebhook = args.b
            tgtoken = args.t
            tgid = args.g
            pptoken = args.k
            fstoken = args.f
            fssecret = args.j
            misaka20001position = args.l
            misakaKey = args.m

        if user_id and user_id.strip():
            user_id = user_id.strip()
            logging.info('user_id 存在')
            # logging.debug(user_id)
        else:
            user_id = False
            logging.info('user_id 不存在')
        if user_password and user_password.strip():
            user_password = user_password.strip()
            logging.info('user_password 存在')
            # logging.debug(user_password)
        else:
            user_password = False
            logging.info('user_password 不存在')
        if Authorization and Authorization.strip():
            Authorization = Authorization.strip()
            logging.info('Authorization 存在')
            # logging.debug(Authorization)
        elif (user_id and user_password):
            Authorization = False
        else:
            Authorization = False
            logging.info('Authorization 不存在')
        if not ((user_id and user_password) or Authorization):
            logging.critical('获取参数错误：请在Secret中保存 登录ID和密码 或 Authorization ！！！')
            parser.print_usage()
            sys.exit(1)
        if Energy_code and Energy_code.strip():
            Energy_code = Energy_code.strip()
            logging.info('Energy_code 存在')
            logging.debug(Energy_code)
        else:
            Energy_code = 'momona'
            logging.debug(Energy_code)
        if resign and resign.strip():
            resign = int(resign.strip())
            if resign > 7:
                resign = 7
            elif resign < 1:
                resign = False
            if resign:
                logging.info('resign 存在')
                logging.debug(resign)
        else:
            resign = False
        if SCKEY and SCKEY.strip():
            SCKEY = SCKEY.strip()
            logging.info('SCKEY 存在')
            # logging.debug(SCKEY)
        else:
            SCKEY = False
        if DDTOKEN and DDTOKEN.strip():
            if DDTOKEN and DDTOKEN.find('access_token=') != -1:
                DDTOKEN = DDTOKEN[DDTOKEN.find('access_token=')+13:]
            DDTOKEN = DDTOKEN.strip()
            logging.info('DDTOKEN 存在')
            # logging.debug(DDTOKEN)
        else:
            DDTOKEN = False
        if DDSECRET and DDSECRET.strip():
            DDSECRET = DDSECRET.strip()
            logging.info('DDSECRET 存在')
            # logging.debug(DDSECRET)
        else:
            DDSECRET = False
        if wxAgentId and wxAgentId.strip():
            wxAgentId = wxAgentId.strip()
            logging.info('wxAgentId 存在')
            # logging.debug(wxAgentId)
        else:
            wxAgentId = False
        if wxSecret and wxSecret.strip():
            wxSecret = wxSecret.strip()
            logging.info('wxSecret 存在')
            # logging.debug(wxSecret)
        else:
            wxSecret = False
        if wxCompanyId and wxCompanyId.strip():
            wxCompanyId = wxCompanyId.strip()
            logging.info('wxCompanyId 存在')
            # logging.debug(wxCompanyId)
        else:
            wxCompanyId = False
        if dcwebhook and dcwebhook.strip():
            dcwebhook = dcwebhook.strip()
            logging.info('dcwebhook 存在')
            # logging.debug(dcwebhook)
        else:
            dcwebhook = False
        if tgtoken and tgtoken.strip():
            tgtoken = tgtoken.strip()
            logging.info('tgtoken 存在')
            # logging.debug(tgtoken)
        else:
            tgtoken = False
        if tgid and tgid.strip():
            tgid = tgid.strip()
            logging.info('tgid 存在')
            # logging.debug(tgid)
        else:
            tgid = False
        if pptoken and pptoken.strip():
            pptoken = pptoken.strip()
            logging.info('pptoken 存在')
            # logging.debug(pptoken)
        else:
            pptoken = False
        if fstoken and fstoken.strip():
            if fstoken and fstoken.find('/hook/') != -1:
                fstoken = fstoken[fstoken.find('/hook/')+6:]
            fstoken = fstoken.strip()
            logging.info('fstoken 存在')
            # logging.debug(fstoken)
        else:
            fstoken = False
        if fssecret and fssecret.strip():
            fssecret = fssecret.strip()
            logging.info('fssecret 存在')
            # logging.debug(fssecret)
        else:
            fssecret = False
        if misaka20001position and misaka20001position.strip():
            misaka20001position = misaka20001position.strip()
            logging.info("misaka20001position 存在")
            # logging.debug(misaka20001position)
        else:
            misaka20001position = False
        if misakaKey and misakaKey.strip():
            misakaKey = misakaKey.strip()
            logging.info("misakakey 存在")
            # logging.debug(misakaKey)
        else:
            misakaKey = False
        logging.info('获取参数结束')
        if SCKEY:
            rs1 = 'Server酱, '
        else:
            rs1 = False
        if (DDTOKEN and DDSECRET):
            rs2 = '钉钉, '
        else:
            rs2 = False
        if (wxAgentId and wxSecret and wxCompanyId):
            rs3 = '企业微信, '
        else:
            rs3 = False
        if dcwebhook:
            rs4 = 'Discord, '
        else:
            rs4 = False
        if pptoken:
            rs5 = 'pptoken, '
        else:
            rs5 = False
        if fstoken and fssecret:
            rs6 = '飞书, '
        else:
            rs6 = False
        if tgtoken and tgid:
            rs7 = 'Telegram, '
        else:
            rs7 = False
        if misaka20001position and misakaKey:
            rs8 = 'misakaNet, '
        else:
            rs8 = False
    except Exception as es:
        logging.critical(es, exc_info=True)
        parser.print_usage()
        # sys.exit(1)

    login_path = 'https://api1.mimikko.cn/client/user/LoginWithPayload'  # 登录(post)
    is_sign = 'https://api1.mimikko.cn/client/user/GetUserSignedInformation'  # 今天是否签到
    history_path = 'https://api1.mimikko.cn/client/dailysignin/log/30/0'  # 签到历史
    can_resign = 'https://api1.mimikko.cn/client/love/getcanresigntimes'  # 补签卡数量
    defeat_set = 'https://api1.mimikko.cn/client/Servant/SetDefaultServant'  # 设置默认助手
    # 补签(post)
    resign_path = 'https://api1.mimikko.cn/client/love/resign?servantId='
    sign_path = 'https://api1.mimikko.cn/client/RewardRuleInfo/SignAndSignInformationV3'  # 签到
    energy_info_path = 'https://api1.mimikko.cn/client/love/GetUserServantInstance'  # 获取助手状态
    energy_reward_path = 'https://api1.mimikko.cn/client/love/ExchangeReward'  # 兑换助手能量
    vip_info = 'https://api1.mimikko.cn/client/user/GetUserVipInfo'  # 获取会员状态
    vip_roll = 'https://api1.mimikko.cn/client/roll/RollReward'  # 会员抽奖(post)
    vip_energy = 'https://api1.mimikko.cn/client/mission/ReceiveMemberLevelWelfare'  # 会员每日领取(post)
    # sc_api = 'https://sc.ftqq.com/' #Server酱推送
    # sct_api = 'https://sctapi.ftqq.com/' #Server酱推送Turbo版
    # ding_api = 'https://oapi.dingtalk.com/robot/send?' # 钉钉推送
    app_Version = '3.2.0'
    app_id = 'wjB7LOP2sYkaMGLC'
    servant_name = {
        'nonona': '诺诺纳',
        'momona': '梦梦奈',
        'ariana': '爱莉安娜',
        'miruku': '米璐库',
        'nemuri': '奈姆利',
        'ruri': '琉璃',
        'alpha0': '阿尔法零',
        'miruku2': '米露可',
        'ulrica': '优莉卡',
        'giwa': '羲和',
        'maya': '摩耶'
    }


    def mimikko():
        logging.info('脚本开始')
        global Authorization
        # 登录
        logging.info('开始登录')
        if user_id and user_password:
            logging.info("使用 ID密码 登录")
            user_password_sha = hashlib.sha256(
                user_password.encode('utf-8')).hexdigest()
            login_data = push.mimikko_login(login_path, app_id, app_Version,
                                    f'{{"password":"{user_password_sha}", "id":"{user_id}"}}')
            logging.debug(login_data)
            if login_data and login_data.get('body'):
                Authorization = login_data['body']['Token']
            if Authorization:
                logging.info("登录成功！")
            else:
                logging.warning("登录错误")
                dddata, scdata, wxdata, dcdata, tgdata, ppdata, fsdata, misakadata = push.AllPush(
                    DDTOKEN, DDSECRET, wxAgentId, wxSecret, wxCompanyId, SCKEY, dcwebhook, tgtoken, tgid, pptoken, fstoken, fssecret, misaka20001position, misakaKey, "兽耳助手签到登录错误", "兽耳助手登录错误，请访问GitHub检查")
                push.push_check(rs1, rs2, rs3, rs4, rs5, rs6, rs7, rs8, dddata, scdata,
                                wxdata, dcdata, tgdata, ppdata, fsdata, misakadata)
                logging.critical('兽耳助手登录错误！！！')
                sys.exit(1)
        else:
            if Authorization:
                logging.info("使用 Authorization 验证")
            else:
                dddata, scdata, wxdata, dcdata, tgdata, ppdata, fsdata, misakadata = push.AllPush(
                    DDTOKEN, DDSECRET, wxAgentId, wxSecret, wxCompanyId, SCKEY, dcwebhook, tgtoken, tgid, pptoken, fstoken, fssecret, misaka20001position, misakaKey, "兽耳助手签到登录错误", "登录错误，未找到 Authorization ，请访问GitHub检查")
                push.push_check(rs1, rs2, rs3, rs4, rs5, rs6, rs7, rs8, dddata, scdata,
                                wxdata, dcdata, tgdata, ppdata, fsdata, misakadata)
                logging.critical('请在Secret中保存 登录ID和密码 或 Authorization ！！！')
                sys.exit(1)
        # 设置默认助手
        time.sleep(random.randint(1,3))
        logging.info(f'设置默认助手{Energy_code}')
        defeat_servant = push.mimikko_get(f'{defeat_set}?code={Energy_code}',
                        app_id, app_Version, Authorization, "")
        logging.debug(defeat_servant)
        # 执行前的好感度
        time.sleep(random.randint(1,3))
        original_energy_data = push.mimikko_get(
            f'{energy_info_path}?code={Energy_code}', app_id, app_Version, Authorization, "")
        logging.debug(original_energy_data)
        if original_energy_data and original_energy_data.get('body'):
            original_energy_post = str(
                original_energy_data['body']['Favorability'])
        else:
            original_energy_post = "Error"
        logging.info(f'执行前的好感度{original_energy_post}')
        # 签到历史
        # time.sleep(random.randint(1,3))
        #logging.info('正在获取签到历史')
        #sign_history = push.mimikko_get(
        #    history_path, app_id, app_Version, Authorization, "")
        #logging.debug(sign_history)
        # 补签
        if resign:
            logging.info("正在尝试补签")
            # 补签前的补签卡
            time.sleep(random.randint(1,3))
            cansign_before = push.mimikko_get(
                can_resign, app_id, app_Version, Authorization, "")
            logging.debug(cansign_before)
            if cansign_before and cansign_before.get('body'):
                cansign_before_time = cansign_before['body']['Value']
            else:
                cansign_before_time = False
            logging.info(f'补签前的补签卡：{cansign_before_time}')
            for i in [1, 2, 3, 4, 5, 6, 7]:
                if not i > resign:
                    logging.info(f'向前第 {i} 天')
                    resign_time = int(time.time())-86400*i
                    r_date = push.timeStamp1time(resign_time)
                    time.sleep(random.randint(1,3))
                    resign_data = push.mimikko_post(
                        resign_path, app_id, app_Version, Authorization, f'["{r_date}T15:59:59+0800"]')
                    logging.debug(resign_data)
                    if resign_data and resign_data["code"] == 0:
                        logging.info("补签成功")
                    else:
                        logging.info("未补签")
                else:
                    break
            # 补签后的补签卡
            time.sleep(random.randint(1,3))
            cansign_after = push.mimikko_get(
                can_resign, app_id, app_Version, Authorization, "")
            logging.debug(cansign_after)
            if cansign_after and cansign_after.get('body'):
                cansign_after_time = cansign_after['body']['Value']
            else:
                cansign_after_time = False
            logging.info(f'补签后的补签卡：{cansign_after_time}')
            # 使用的补签卡
            if cansign_before_time and cansign_after_time:
                times_resigned = cansign_after_time-cansign_before_time
            else:
                times_resigned = False
            logging.info(f'消耗 {times_resigned} 张')
        else:
            times_resigned = False
        # 签到
        time.sleep(random.randint(1,3))
        logging.info('正在尝试签到')
        sign_data = push.mimikko_get(sign_path, app_id, app_Version, Authorization, "")
        logging.debug(sign_data)
        if sign_data and sign_data.get('body'):
            time.sleep(random.randint(1,3))
            sign_info = push.mimikko_get(
                is_sign, app_id, app_Version, Authorization, "")
            logging.debug(sign_info)
            if sign_data['body']['GetExp']:
                if times_resigned:
                    sign_result_post = f'''补签成功{str(times_resigned)}/{str(resign)}天\n签到成功：{str(sign_info['body']['ContinuousSignDays'])}天\n好感度：{str(sign_data['body']['Reward'])}\n硬币：{str(sign_data['body']['GetCoin'])}\n经验值：{str(sign_data['body']['GetExp'])}\n签到卡片：{sign_data['body']['Description']}{sign_data['body']['Name']}\n{sign_data['body']['PictureUrl']}'''
                else:
                    sign_result_post = f'''签到成功：{str(sign_info['body']['ContinuousSignDays'])}天\n好感度：{str(sign_data['body']['Reward'])}\n硬币：{str(sign_data['body']['GetCoin'])}\n经验值：{str(sign_data['body']['GetExp'])}\n签到卡片：{sign_data['body']['Description']}{sign_data['body']['Name']}\n{sign_data['body']['PictureUrl']}'''
                title_ahead = f'''兽耳助手签到{str(sign_info['body']['ContinuousSignDays'])}'''
            else:
                sign_result_post = f'''今日已签到：{str(sign_info['body']['ContinuousSignDays'])}天\n签到卡片：{sign_data['body']['Description']}{sign_data['body']['Name']}\n{sign_data['body']['PictureUrl']}'''
                title_ahead = f'''兽耳助手签到{str(sign_info['body']['ContinuousSignDays'])}'''
        else:
            sign_result_post = '签到失败'
            title_ahead = '兽耳助手签到'
        logging.info(title_ahead)
        # VIP抽奖
        time.sleep(random.randint(1,3))
        logging.info('正在尝试VIP抽奖')
        vip_info_data = push.mimikko_get(
            vip_info, app_id, app_Version, Authorization, "")
        logging.debug(vip_info_data)
        if vip_info_data and vip_info_data.get('body'):
            if vip_info_data['body']['rollNum'] > 0:
                time.sleep(random.randint(1,3))
                vip_roll_data = push.mimikko_post(
                    vip_roll, app_id, app_Version, Authorization, "")
                logging.debug(vip_roll_data)
                if vip_roll_data['body']['Value']['message']==None:
                    vip_roll_msg = f'''VIP抽奖成功：{vip_roll_data['body']['Value']['description']}'''
                else:
                    vip_roll_msg = f'''VIP抽奖失败：{vip_roll_data['body']['Value']['message']}'''
            else:
                vip_roll_data = "抽奖次数不足"
                if vip_info_data['body']['isValid']:
                    vip_roll_msg = "VIP抽奖失败：今天已经抽过奖了"
                else:
                    vip_roll_msg = "VIP抽奖失败：您还不是VIP"
            if vip_info_data['body']['isValid']:
                time.sleep(random.randint(1,3))
                vip_energy_data = push.mimikko_post(
                    vip_energy, app_id, app_Version, Authorization, "")
                logging.debug(vip_energy_data)
                if vip_energy_data['ok']:
                    vip_energy_msg = f'''VIP能量领取成功：{vip_energy_data['body']['Value']['message']}'''
                else:
                    vip_energy_msg = f'''VIP能量领取失败：{vip_energy_data['msg']}'''
            else:
                vip_energy_msg = "VIP能量领取失败：您还不是VIP"
            vip_roll_post = f'''{vip_roll_msg}\n{vip_energy_msg}'''
        else:
            vip_roll_data = "VIP信息获取失败"
            vip_roll_post = "VIP信息获取失败，未抽奖和领取能量"
        logging.info(vip_roll_msg)
        logging.info(vip_energy_msg)
        # 能量兑换好感度
        logging.info('正在尝试兑换能量')
        if not original_energy_data:
            time.sleep(random.randint(1,3))
            original_energy_data = push.mimikko_get(
                f'{energy_info_path}?code={Energy_code}', app_id, app_Version, Authorization, "")
            logging.debug(original_energy_data)
        if original_energy_data and original_energy_data.get('body'):
            if original_energy_data['body']['Energy'] > 0:
                time.sleep(random.randint(1,3))
                energy_reward_data = push.mimikko_get(
                    f'{energy_reward_path}?code={Energy_code}', app_id, app_Version, Authorization, "")
                logging.debug(energy_reward_data)
                title_post = f'''{title_ahead}{servant_name[energy_reward_data['body']['code']]}好感度{str(energy_reward_data['body']['Favorability'])}'''
                gethgd = int(
                    energy_reward_data['body']['Favorability'])-int(original_energy_post)
                energy_reward_post = f'''能量值：{str(original_energy_data['body']['Energy'])}/{str(original_energy_data['body']['MaxEnergy'])}\n好感度兑换成功\n助手：{servant_name[energy_reward_data['body']['code']]} LV{str(energy_reward_data['body']['Level'])} +{gethgd}({original_energy_post}→{str(energy_reward_data['body']['Favorability'])}/{str(original_energy_data['body']['MaxFavorability'])})'''
                logging.info('兑换成功')
            else:
                energy_reward_data = "您的能量值不足，无法兑换"
                title_post = f'''{title_ahead}{servant_name[original_energy_data['body']['code']]}好感度{str(original_energy_data['body']['Favorability'])}'''
                gethgd = int(
                    original_energy_data['body']['Favorability'])-int(original_energy_post)
                energy_reward_post = f'''能量值：{str(original_energy_data['body']['Energy'])}/{str(original_energy_data['body']['MaxEnergy'])}\n好感度兑换失败：当前没有能量\n助手：{servant_name[original_energy_data['body']['code']]} LV{str(original_energy_data['body']['Level'])} +{gethgd}({original_energy_post}→{str(original_energy_data['body']['Favorability'])}/{str(original_energy_data['body']['MaxFavorability'])})'''
                logging.info(energy_reward_data)
        else:
            energy_reward_data = "能量兑换失败"
            title_post = title_ahead
            gethgd = 0
            energy_reward_post = "能量兑换失败"
            logging.info(energy_reward_data)
        logging.info('脚本结束')
        return sign_data, vip_info_data, vip_roll_data, original_energy_data, energy_reward_data, sign_info, sign_result_post, title_post, vip_roll_post, energy_reward_post


    try:
        sign_data, vip_info_data, vip_roll_data, original_energy_data, energy_reward_data, sign_info, sign_result_post, title_post, vip_roll_post, energy_reward_post = mimikko()
        varErr = True
        varErrText = ''
        for i in ['sign_data', 'vip_info_data', 'vip_roll_data', 'original_energy_data', 'energy_reward_data', 'sign_info', 'sign_result_post', 'title_post', 'vip_roll_post', 'energy_reward_post']:
            if not i in locals():
                varErr = False
                logging.warning(f'{i} 缺失')
                varErrText = f'{varErrText},{i}'
        if varErr:
            now_time = push.timeStamp2time(time.time()+28800)
            post_text = re.sub(
                '\\n', '  \n', f'现在是：{now_time}\n{sign_result_post}\n{vip_roll_post}\n{energy_reward_post}')
        else:
            varErrText = f'函数返回值 {varErrText[1:]} 缺失'
    except Exception as em:
        varErr = False
        varErrText = f'Error: {em}'
        logging.critical(em, exc_info=True)

    try:
        if varErr:
            logging.info("运行成功，正在推送")
            dddata, scdata, wxdata, dcdata, tgdata, ppdata, fsdata, misakadata = push.AllPush(
                DDTOKEN, DDSECRET, wxAgentId, wxSecret, wxCompanyId, SCKEY, dcwebhook, tgtoken, tgid, pptoken, fstoken, fssecret, misaka20001position, misakaKey, title_post, post_text)
            push.push_check(rs1, rs2, rs3, rs4, rs5, rs6, rs7, rs8, dddata, scdata,
                            wxdata, dcdata, tgdata, ppdata, fsdata, misakadata)
            rs1, rs2, rs3, rs4, rs5, rs6, rs7, rs8 = push.rs_check(
                rs1, rs2, rs3, rs4, rs5, rs6, rs7, rs8, dddata, scdata, wxdata, dcdata, tgdata, ppdata, fsdata, misakadata)
            logging.info(f'All Finish!\n\n推送信息：\n\n{title_post}\n{post_text}')
        else:
            logging.warning("运行失败，正在推送")
            logging.warning(f"兽耳助手签到数据异常，请访问GitHub检查：“{varErrText}”")
            dddata, scdata, wxdata, dcdata, tgdata, ppdata, fsdata, misakadata = push.AllPush(
                DDTOKEN, DDSECRET, wxAgentId, wxSecret, wxCompanyId, SCKEY, dcwebhook, tgtoken, tgid, pptoken, fstoken, fssecret, misaka20001position, misakaKey, "兽耳助手签到数据异常", f'兽耳助手签到数据异常，请访问GitHub检查：“{varErrText}”')
            push.push_check(rs1, rs2, rs3, rs4, rs5, rs6, rs7, rs8, dddata, scdata,
                            wxdata, dcdata, tgdata, ppdata, fsdata, misakadata)
            rs1, rs2, rs3, rs4, rs5, rs6, rs7, rs8 = push.rs_check(
                rs1, rs2, rs3, rs4, rs5, rs6, rs7, rs8, dddata, scdata, wxdata, dcdata, tgdata, ppdata, fsdata, misakadata)
    except Exception as es:
        logging.warning("数据异常，尝试推送")
        if not rs1:
            SCKEY = False
        if not rs2:
            DDTOKEN = DDSECRET = False
        if not rs3:
            wxAgentId = wxSecret = wxCompanyId = False
        if not rs4:
            dcwebhook = False
        if not rs5:
            pptoken = False
        if not rs6:
            fstoken = fssecret = False
        dddata, scdata, wxdata, dcdata, tgdata, ppdata, fsdata, misakadata = push.AllPush(
            DDTOKEN, DDSECRET, wxAgentId, wxSecret, wxCompanyId, SCKEY, dcwebhook, tgtoken, tgid, pptoken, fstoken, fssecret, misaka20001position, misakaKey, "兽耳助手签到数据异常", f"兽耳助手签到数据异常，请访问GitHub检查：{es}")
        push.push_check(rs1, rs2, rs3, rs4, rs5, rs6, rs7, rs8, dddata, scdata,
                        wxdata, dcdata, tgdata, ppdata, fsdata, misakadata)
        rs1, rs2, rs3, rs4, rs5, rs6, rs7, rs8 = push.rs_check(
            rs1, rs2, rs3, rs4, rs5, rs6, rs7, rs8, dddata, scdata, wxdata, dcdata, tgdata, ppdata, fsdata, misakadata)
        logging.error(es, exc_info=True)

    #if rs1 or rs2 or rs3 or rs4 or rs5 or rs6 or rs7 or rs8:
    #    logging.warning(re.sub(',  ', ' ', re.sub(
    #        'False', '', f'{rs1}{rs2}{rs3}{rs4}{rs5}{rs6}{rs7}{rs8} 推送异常，请检查')))
    #    sys.exit(2)
    return

if(options["isServerless"]=="False"):
    main()
