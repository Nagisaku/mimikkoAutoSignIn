# -*- coding: UTF-8 -*-
"""
 * @author  cyb233
 * @date  2021/4/18
"""
import base64
import hashlib
import hmac
import json
import logging
import re
import time
import urllib.parse

import requests
import telebot
from urllib3.exceptions import InsecureRequestWarning

requests.urllib3.disable_warnings(InsecureRequestWarning)

_MAX_TRIES = 5


def mimikko_login(url, app_id, app_Version, params):      # 带尝试的登录post
    returnValue = False
    i = 1
    while True:
        logging.debug(f"第{i}次尝试登录")
        returnValue = mimikko_realLogin(url, app_id, app_Version, params)
        if returnValue != False:
            logging.debug("SUCCESS")
            break
        if i == _MAX_TRIES:
            logging.warning(f"{_MAX_TRIES}次请求失败，已跳过")
            break

    return returnValue


def mimikko_realLogin(url, app_id, app_Version, params):  # 实际登录post
    headers = {
        'Accept': 'application/json',
        'Cache-Control': 'no-cache',
        'AppID': app_id,
        'Version': app_Version,
        'Content-Type': 'application/json',
        'Host': 'api1.mimikko.cn',
        'Accept-Encoding': 'gzip',
        'User-Agent': 'okhttp/3.12.1',
    }
    try:
        with requests.post(url, headers=headers, data=params, timeout=300) as resp:
            # logging.debug(resp.text)  # 请务必谨慎开启，因为包含 Authorization 参数！！！
            res = resp.json()
            return res
    except Exception as exl:
        logging.error(exl, exc_info=True)
        return False


def mimikko_get(url, app_id, app_Version, Authorization, params):      # 带尝试的get
    returnValue = False
    i = 1
    while True:
        logging.debug(f"第{i}次尝试GET")
        returnValue = mimikko_realGet(
            url, app_id, app_Version, Authorization, params)
        if returnValue != False:
            logging.debug("SUCCESS")
            break
        if i == _MAX_TRIES:
            logging.warning(f"{_MAX_TRIES}次请求失败，已跳过")
            break

    return returnValue


def mimikko_realGet(url, app_id, app_Version, Authorization, params):  # 实际get请求
    headers = {
        'Cache-Control': 'Cache-Control:public,no-cache',
        'Accept-Encoding': 'gzip',
        'User-Agent': 'Mozilla/5.0(Linux;Android6.0.1;MuMu Build/V417IR;wv)AppleWebKit/537.36(KHTML,like Gecko)Version/4.0 Chrome/52.0.2743.100MobileSafari / 537.36',
        'AppID': app_id,
        'Version': app_Version,
        'Authorization': Authorization,
        'Host': 'api1.mimikko.cn'
    }
    try:
        with requests.get(url, headers=headers, params=params, timeout=300) as resp:
            logging.debug(resp.text)
            res = resp.json()
            return res
    except Exception as exg:
        logging.error(exg, exc_info=True)
        return False


def mimikko_post(url, app_id, app_Version, Authorization, params):      # 带尝试的post
    returnValue = False
    i = 1
    while True:
        logging.debug(f"第{i}次尝试POST")
        returnValue = mimikko_realPost(
            url, app_id, app_Version, Authorization, params)
        if returnValue != False:
            logging.debug("SUCCESS")
            break
        if i == _MAX_TRIES:
            logging.warning(f"{_MAX_TRIES}次请求失败，已跳过")
            break

    return returnValue


def mimikko_realPost(url, app_id, app_Version, Authorization, params):  # post请求
    headers = {
        'Accept': 'application/json',
        'Cache-Control': 'no-cache',
        'AppID': app_id,
        'Version': app_Version,
        'Authorization': Authorization,
        'Content-Type': 'application/json',
        'Host': 'api1.mimikko.cn',
        'Accept-Encoding': 'gzip',
        'User-Agent': 'okhttp/3.12.1',
    }
    try:
        with requests.post(url, headers=headers, data=params, timeout=300) as resp:
            logging.debug(resp.text)
            res = resp.json()
            return res
    except Exception as exp:
        logging.error(exp, exc_info=True)
        return False


def timeStamp1time(timeStamp):  # 时间格式化1
    timeArray = time.localtime(timeStamp)
    StyleTime = time.strftime('%Y-%m-%d', timeArray)
    return StyleTime


def timeStamp2time(timeStamp):  # 时间格式化2
    timeArray = time.localtime(timeStamp)
    StyleTime = time.strftime('%Y年%m月%d日 %H:%M:%S', timeArray)
    return StyleTime


def ddpost(DDTOKEN, DDSECRET, title_post, post_text):  # 钉钉推送
    timestamp = str(round(time.time() * 1000))
    secret_enc = DDSECRET.encode('utf-8')
    string_to_sign = f'{timestamp}\n{DDSECRET}'
    string_to_sign_enc = string_to_sign.encode('utf-8')
    hmac_code = hmac.new(secret_enc, string_to_sign_enc,
                         digestmod=hashlib.sha256).digest()
    sign = urllib.parse.quote_plus(base64.b64encode(hmac_code))
    headers_post = {
        'Content-Type': 'application/json; charset=UTF-8',
    }
    url = f'https://oapi.dingtalk.com/robot/send?access_token={DDTOKEN}&timestamp={timestamp}&sign={sign}'
    post_info = {
        "msgtype": "text",
        "text": {
            "content": f'{title_post}\n\n{post_text}'
        }
    }
    post_info = json.dumps(post_info)
    try:
        with requests.post(url, headers=headers_post, data=post_info, timeout=300) as post_data:
            logging.debug(post_data.text)
            if 'errcode' in post_data.json() and post_data.json()["errcode"] == 0:
                return post_data.json()["errcode"]
            else:
                return post_data.text
    except Exception as exp:
        logging.error(exp, exc_info=True)
        return exp


def scpost(SCKEY, title_post, post_text):  # server酱推送
    headers_post = {
        'Content-Type': 'application/x-www-form-urlencoded',
    }
    post_info = {'text': title_post, 'desp': post_text}
    url = f'https://sctapi.ftqq.com/{SCKEY}.send'
    try:
        with requests.post(url, headers=headers_post, data=post_info, timeout=300) as post_data:
            logging.debug(post_data.text)
            if 'errno' in post_data.json() and post_data.json()["errno"] == 0:
                return post_data.json()["errno"]
            else:
                return post_data.text
    except Exception as exp:
        logging.error(exp, exc_info=True)
        return exp


def send2wechat(wxAgentId, wxSecret, wxCompanyId, title_post, post_text):  # 企业微信推送
    """
    # 此段修改自https://www.jianshu.com/p/99f706f1e943
    :param AgentId: 应用ID
    :param Secret: 应用Secret
    :param CompanyId: 企业ID
    """
    # 通行密钥
    ACCESS_TOKEN = None
    ATurl = f'https://qyapi.weixin.qq.com/cgi-bin/gettoken?corpid={wxCompanyId}&corpsecret={wxSecret}'
    try:
        # 通过企业ID和应用Secret获取本地通行密钥
        with requests.get(ATurl, timeout=300) as r:
            logging.debug(r.text)
            r = r.json()
            ACCESS_TOKEN = r["access_token"]
    except Exception as exp:
        logging.error(exp, exc_info=True)
        return exp
    # logging.debug(ACCESS_TOKEN)  # 注意账号安全
    # 要发送的信息格式
    data = {
        "touser": "@all",
        "msgtype": "text",
        "agentid": f"{wxAgentId}",
        "text": {"content": f'{title_post}\n\n{post_text}'}
    }
    # 字典转成json，不然会报错
    data = json.dumps(data)
    url = f'https://qyapi.weixin.qq.com/cgi-bin/message/send?access_token={ACCESS_TOKEN}'
    try:
        if ACCESS_TOKEN:
            # 发送消息
            with requests.post(url, data=data, timeout=300) as post_data:
                logging.debug(post_data.text)
                if 'errcode' in post_data.json() and post_data.json()["errcode"] == 0:
                    return post_data.json()["errcode"]
                else:
                    return post_data.text
        else:
            return 'ACCESS_TOKEN获取失败，未发送'
    except Exception as exp:
        logging.error(exp, exc_info=True)
        return exp


def dcpost(dcwebhook, title_post, post_text):  # Discord推送
    url = dcwebhook
    headers = {"Content-Type": "application/json"}
    data = {"content": f'{title_post}\n\n{post_text}'}
    try:
        # 发送消息
        with requests.post(url, headers=headers, data=json.dumps(data), timeout=300) as post_data:
            logging.debug(post_data.text)
            return post_data
    except Exception as exp:
        logging.error(exp, exc_info=True)
        return exp


def tgpost(tgtoken, tgid, title_post, post_text):  # Telegram推送
    try:
        # 发送消息
        bot = telebot.TeleBot(tgtoken)
        data = bot.send_message(tgid, f'{title_post}\n\n{post_text}')
        return data.id
    except Exception as exp:
        logging.error(exp, exc_info=True)
        return exp


def pppost(pptoken, title_post, post_text):  # PushPlus推送
    url = f'http://pushplus.hxtrip.com/send/{pptoken}'
    headers = {"Content-Type": "application/json"}
    data = {"title": title_post, "content": post_text}
    try:
        # 发送消息
        with requests.post(url, headers=headers, data=json.dumps(data), timeout=300) as post_data:
            logging.debug(post_data.text)
            if 'code' in post_data.json() and post_data.json()["code"] == 0:
                return post_data.json()["code"]
            else:
                return post_data.text
            return post_data
    except Exception as exp:
        logging.error(exp, exc_info=True)
        return exp


def fspost(fstoken, fssecret, title_post, post_text):  # 飞书推送
    timestamp = str(round(time.time()))
    secret = fssecret
    key = f'{timestamp}\n{secret}'
    key_enc = key.encode('utf-8')
    msg = ""
    msg_enc = msg.encode('utf-8')
    hmac_code = hmac.new(key_enc, msg_enc, digestmod=hashlib.sha256).digest()
    sign = base64.b64encode(hmac_code).decode('utf-8')
    print(timestamp)
    print(sign)
    headers_post = {
        'Content-Type': 'application/json; charset=UTF-8',
    }
    url = f'https://open.feishu.cn/open-apis/bot/v2/hook/{fstoken}'
    post_info = {
        "timestamp": timestamp,
        "sign": sign,
        "msg_type": "text",
        "content": {
            "text": f'{title_post}\n\n{post_text}'
        }
    }
    post_info = json.dumps(post_info)
    try:
        with requests.post(url, headers=headers_post, data=post_info, timeout=300) as post_data:
            logging.debug(post_data.text)
            if 'StatusCode' in post_data.json() and post_data.json()["StatusCode"] == 0:
                return post_data.json()["StatusCode"]
            else:
                return post_data.text
    except Exception as exp:
        logging.error(exp, exc_info=True)
        return exp

def misakapost(misaka20001position, misakaKey, title_post, post_text):  #MisakaNet推送
    headers_post = {
        "misaka-key": misakaKey
    }
    try:
        with requests.post(misaka20001position, headers=headers_post, data=f'{title_post}\n\n{post_text}'.encode('utf-8'), timeout=300) as post_data:
            logging.debug(post_data)
            return post_data.json()

    except Exception as exp:
        logging.error(exp, exc_info=True)
        return exp

def AllPush(DDTOKEN, DDSECRET, wxAgentId, wxSecret, wxCompanyId, SCKEY, dcwebhook, tgtoken, tgid, pptoken, fstoken, fssecret, misaka20001position, misakaKey, title_post, post_text):  # 全推送
    dddata = scdata = wxdata = dcdata = tgdata = ppdata = fsdata = misakadata = False
    if SCKEY:
        logging.info("正在推送到Server酱")
        scdata = scpost(SCKEY, title_post, post_text)  # server酱推送
    else:
        logging.info('SCKEY不存在')
    if DDTOKEN and DDSECRET:
        logging.info("正在推送到钉钉")
        dddata = ddpost(DDTOKEN, DDSECRET, title_post, post_text)  # 钉钉推送
    else:
        logging.info('DDTOKEN或DDSECRET不存在')
    if wxAgentId and wxSecret and wxCompanyId:
        logging.info("正在推送到企业微信")
        wxdata = send2wechat(wxAgentId, wxSecret, wxCompanyId,
                             title_post, post_text)  # 企业微信推送
    else:
        logging.info('wxAgentId, wxSecret或wxCompanyId不存在')
    if dcwebhook:
        logging.info("正在推送到Discord")
        dcdata = dcpost(dcwebhook, title_post, post_text)  # Discord推送
    else:
        logging.info('dcwebhook不存在')
    if tgtoken and tgid:
        logging.info("正在推送到Telegram")
        tgdata = tgpost(tgtoken, tgid, title_post, post_text)  # Telegram推送
    else:
        logging.info('tgtoken或tgid不存在')
    if pptoken:
        logging.info("正在推送到PushPlus")
        ppdata = pppost(pptoken, title_post, post_text)  # PushPlus推送
    else:
        logging.info('pptoken不存在')
    if fstoken and fssecret:
        logging.info("正在推送到飞书")
        fsdata = pppost(pptoken, title_post, post_text)  # 飞书推送
    else:
        logging.info('fstoken或fssecret不存在')
    if misaka20001position and misakaKey:
        logging.info("正在推送到misakaNet")
        misakadata = misakapost(misaka20001position, misakaKey, title_post, post_text)
    else:
        logging.info("misaka20001position或misakaKey不存在")
    return dddata, scdata, wxdata, dcdata, tgdata, ppdata, fsdata, misakadata


def push_check(rs1, rs2, rs3, rs4, rs5, rs6, rs7, rs8, dddata, scdata, wxdata, dcdata, tgdata, ppdata, fsdata, misakadata):
    if rs1:
        if str(scdata) == '0':
            logging.info(f'server酱 errcode: {scdata}')
        else:
            logging.warning(f'server酱 error: {scdata}')
    if rs2:
        if str(dddata) == '0':
            logging.info(f'钉钉 errcode: {dddata}')
        else:
            logging.warning(f'钉钉 error: {dddata}')
    if rs3:
        if str(wxdata) == '0':
            logging.info(f'企业微信 errcode: {wxdata}')
        else:
            logging.warning(f'企业微信 error: {wxdata}')
    if rs4:
        if not str(dcdata) == 'False':
            logging.info(f'Discord: {dcdata}')
        else:
            logging.warning(f'Discord error: {dcdata}')
    if rs5:
        if ppdata == 200:
            logging.info(f'PushPlus errcode: {ppdata}')
        else:
            logging.warning(f'PushPlus error: {ppdata}')
    if rs6:
        if str(fsdata) == '0':
            logging.info(f'飞书 errcode: {fsdata}')
        else:
            logging.warning(f'飞书 error: {fsdata}')
    if rs7:
        if type(tgdata) == int:
            logging.info(f'Telegram msgcode: {tgdata}')
        else:
            logging.warning(f'Telegram error: {tgdata}')
    if rs8:
        if misakadata["OK"]:
            logging.info("MisakaNet done")
        else:
            logging.info(f"MisakaNet error: {misakadata['error']}")


def rs_check(rs1, rs2, rs3, rs4, rs5, rs6, rs7, rs8, dddata, scdata, wxdata, dcdata, tgdata, ppdata, fsdata, misakadata):
    if rs1 and str(scdata) == '0':
        rs1 = False
    if rs2 and str(dddata) == '0':
        rs2 = False
    if rs3 and str(wxdata) == '0':
        rs3 = False
    if rs4 and not str(dcdata) == 'False':
        rs4 = False
    if rs5 and ppdata == 200:
        rs5 = False
    if rs6 and str(fsdata) == '0':
        rs6 = False
    if rs7 and type(tgdata) == int:
        rs7 = False
    if rs8 and misakadata["OK"]:
        rs8 = False
    return rs1, rs2, rs3, rs4, rs5, rs6, rs7, rs8
