#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
中国联通采购与招标网标讯日报推送 v1.2.0
数据源: https://www.chinaunicombidding.cn
API: POST /api/v1/bizAnno/getAnnoList
详情: GET /api/v1/bizAnno/getAnnoDetailed/{id}
"""

import json
import re
import sys
import urllib.request
import urllib.error
from datetime import datetime, timedelta

# ==================== 配置 ====================

BASE_URL = "https://www.chinaunicombidding.cn"
LIST_API = f"{BASE_URL}/api/v1/bizAnno/getAnnoList"
DETAIL_API = f"{BASE_URL}/api/v1/bizAnno/getAnnoDetailed"
DETAIL_PAGE = f"{BASE_URL}/bidInformation/detail?id="

HEADERS = {
    "Content-Type": "application/json;charset=UTF-8",
    "Accept": "application/json",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Referer": f"{BASE_URL}/bidInformation",
}

# 网安关键词（与移动/电信统一）
KEYWORDS = [
    "安全", "网安", "信安", "等保", "合规", "反诈", "涉诈",
    "漏洞", "攻防", "渗透", "渗透测试", "漏洞管理",
    "态势感知", "威胁情报", "威胁分析", "威胁", "暴露面",
    "防火墙", "WAF", "入侵检测", "数据防泄漏", "加密",
    "DDOS", "抗D", "流量清洗", "僵木蠕", "个人信息保护",
    "信息安全", "网络安全",
]

# 排除词（建筑/交通/物理安全等假阳性）
EXCLUDE_WORDS = [
    "房屋建筑", "构筑物", "安全隐患", "安全鉴定", "安全检测",
    "安全评估", "房屋结构", "建筑安全", "结构安全", "抗震鉴定",
    "装修", "装修改造", "土建", "绿化", "保洁", "食堂",
    "交通安全", "车载安全", "车辆安全", "车载主动安全", "机动车安全",
    "道路交通", "道路交安",
    "安全门", "安全防护用品", "安全巡检", "安全帽", "安全隐患整改",
    "门禁", "视频监控", "视频图像", "防雷检测",
    "智慧工地", "工地安全", "建筑工地", "施工安全",
    "生命线安全", "基础设施安全", "市政安全",
    "安全生产", "特种作业", "安全作业",
    "加密对讲", "加密卡", "量子加密对讲", "密码井",
]

REAL_CYBER_KEYWORDS = [
    "网安", "信安", "等保", "漏洞", "攻防", "渗透", "防火墙", "WAF",
    "入侵", "数据防泄漏", "态势感知", "威胁", "DDOS", "抗D",
    "流量清洗", "僵木蠕", "个人信息", "信息安全", "网络安全",
    "反诈", "涉诈", "合规", "加密",
]

# 省份映射：从bidCompany或标题提取
PROVINCE_MAP = {
    "北京": "北京", "天津": "天津", "上海": "上海", "重庆": "重庆",
    "河北": "河北", "山西": "山西", "辽宁": "辽宁", "吉林": "吉林",
    "黑龙江": "黑龙江", "江苏": "江苏", "浙江": "浙江", "安徽": "安徽",
    "福建": "福建", "江西": "江西", "山东": "山东", "河南": "河南",
    "湖北": "湖北", "湖南": "湖南", "广东": "广东", "海南": "海南",
    "四川": "四川", "贵州": "贵州", "云南": "云南", "陕西": "陕西",
    "甘肃": "甘肃", "青海": "青海", "台湾": "台湾",
    "内蒙古": "内蒙古", "广西": "广西", "西藏": "西藏",
    "宁夏": "宁夏", "新疆": "新疆",
    # 特殊映射
    "产互": "广东",  # 联通产互公司总部在广州
}


def api_post(url, data):
    body = json.dumps(data).encode("utf-8")
    req = urllib.request.Request(url, data=body, headers=HEADERS, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception as e:
        print(f"[ERROR] API请求失败: {e}", file=sys.stderr)
        return None


def api_get(url):
    req = urllib.request.Request(url, headers=HEADERS, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception as e:
        print(f"[ERROR] API请求失败: {e}", file=sys.stderr)
        return None


def clean_html(html_text):
    if not html_text:
        return ""
    text = re.sub(r"<[^>]+>", "", html_text)
    text = text.replace("&nbsp;", " ").replace("&amp;", "&")
    # 清理特殊字符（如 U+20AC⁬）
    text = re.sub(r"[\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff\u20ac]", "", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text


def clean_title(title):
    return title[:40] if title else ""


def is_cybersecurity(title):
    for exc in EXCLUDE_WORDS:
        if exc in title:
            return False
    for kw in KEYWORDS:
        if kw in title:
            if kw == "安全":
                has_real = any(rk in title for rk in REAL_CYBER_KEYWORDS)
                if not has_real:
                    return False
            return True
    return False


def infer_province(item):
    """从bidCompany或标题推断省份"""
    # 优先使用API返回的省份
    prov = item.get("provinceName", "")
    if prov and prov != "其他":
        return prov

    # 从bidCompany提取
    company = item.get("bidCompany", "")
    for p, name in PROVINCE_MAP.items():
        if p in company:
            return name

    # 从标题提取
    title = item.get("annoName", "")
    for p, name in PROVINCE_MAP.items():
        if p in title:
            return name

    return "其他"


def extract_winner(anno_text):
    """从详情页文本提取中标厂商"""
    text = clean_html(anno_text)
    winners = []

    # 模式1: "中选[候]候选人如下：公司名"（兼容错别字"侯选人"）
    m = re.search(r"中选[候侯]选人如下[：:]\s*(.+?)(?:\d+[、.]|公示期|公示媒|联系方式|$)", text)
    if m:
        chunk = m.group(1)
        # 提取公司名（支持带括号的公司名）
        names = re.findall(r"(?:第[一二三四五六七八九十\d]+名[：:]\s*)?([\u4e00-\u9fa5（）\(\)]+(?:有限公司|股份公司|集团|有限责任公司))", chunk)
        if names:
            winners = [n.strip() for n in names if len(n.strip()) > 4]

    # 模式2: "成交候选人如下：公司名"
    if not winners:
        m = re.search(r"成交候选人如下[：:]\s*([\u4e00-\u9fa5（）\(\)]+(?:有限公司|股份公司|集团|有限责任公司))", text)
        if m:
            winners = [m.group(1).strip()]

    # 模式3: "成交供应商：公司名"
    if not winners:
        m = re.search(r"成交[供]?应商[：:]\s*([\u4e00-\u9fa5（）\(\)]+(?:有限公司|股份公司|集团|有限责任公司))", text)
        if m:
            winners = [m.group(1).strip()]

    # 模式4: "中选人：公司名"
    if not winners:
        m = re.search(r"中选人[：:]\s*([\u4e00-\u9fa5（）\(\)]+(?:有限公司|股份公司|集团|有限责任公司))", text)
        if m:
            winners = [m.group(1).strip()]

    # 模式5: "中标人：公司名"
    if not winners:
        m = re.search(r"中标人[：:]\s*([\u4e00-\u9fa5（）\(\)]+(?:有限公司|股份公司|集团|有限责任公司))", text)
        if m:
            winners = [m.group(1).strip()]

    # 模式6: "第一名：公司名" 或 "1. 公司名"
    if not winners:
        for m in re.finditer(r"第[一二三123]名[：:.\s]*([\u4e00-\u9fa5（）\(\)]{4,50}?(?:有限公司|股份公司|集团|有限责任公司))", text):
            winners.append(m.group(1).strip())

    return "、".join(winners[:3]) if winners else "-"


def extract_price(anno_text):
    """从详情页文本提取金额"""
    text = clean_html(anno_text)
    patterns = [
        r"最高限价[为：:]\s*(?:不含增值税总价)?(?:最高)?限价[为：:]\s*(?:为|是)?\s*([\d,\.]+)\s*(万元|元|万)",
        r"最高限价[为：:]\s*(?:为|是)?\s*([\d,\.]+)\s*(万元|元|万)",
        r"预算[为：:]\s*(?:为|是)?\s*([\d,\.]+)\s*(万元|元|万)",
        r"采购金额[为：:]\s*(?:为|是)?\s*([\d,\.]+)\s*(万元|元|万)",
        r"项目预算[为：:]\s*(?:为|是)?\s*([\d,\.]+)\s*(万元|元|万)",
        r"总价[为：:]\s*(?:为|是)?\s*([\d,\.]+)\s*(万元|元|万)",
    ]
    for pat in patterns:
        m = re.search(pat, text)
        if m:
            val = m.group(1).replace(",", "")
            return f"{val}{m.group(2)}"
    # 兜底：提取任何金额
    m = re.search(r"([\d,\.]+)\s*(万元|元|万)", text)
    if m:
        val = m.group(1).replace(",", "")
        return f"{val}{m.group(2)}"
    return "-"


def fetch_list(keyword, page_size=50):
    data = {
        "pageNo": 1,
        "pageSize": page_size,
        "modeNo": "BizAnnoVoMtable",
        "annoName": keyword,
    }
    resp = api_post(LIST_API, data)
    if not resp or not resp.get("success"):
        return []
    return resp.get("data", {}).get("records", [])


def fetch_detail(item_id):
    url = f"{DETAIL_API}/{item_id}"
    resp = api_get(url)
    if not resp or not resp.get("success"):
        return None
    return resp.get("data")


def main():
    cutoff_date = (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d")
    today = datetime.now().strftime("%Y-%m-%d")
    print(f"查询范围: {cutoff_date} ~ {today}", file=sys.stderr)

    # 收集所有标讯
    all_items = {}
    for kw in KEYWORDS:
        records = fetch_list(kw)
        for r in records:
            item_id = r["id"]
            if item_id not in all_items:
                all_items[item_id] = r

    # 按日期过滤 + 网安过滤
    filtered = []
    for item_id, r in all_items.items():
        create_date = r.get("createDate", "")[:10]
        title = r.get("annoName", "")
        if create_date >= cutoff_date and is_cybersecurity(title):
            # 推断省份
            r["inferredProvince"] = infer_province(r)
            filtered.append(r)

    # 按类型分组
    procurement_results = []
    procurement_announcements = []

    for r in filtered:
        anno_type = r.get("annoType", "")
        if anno_type == "采购结果":
            procurement_results.append(r)
        elif anno_type == "采购公告":
            procurement_announcements.append(r)

    procurement_results.sort(key=lambda x: x.get("createDate", ""), reverse=True)
    procurement_announcements.sort(key=lambda x: x.get("createDate", ""), reverse=True)

    # 提取详情
    print(f"提取详情: 采购结果{len(procurement_results)}条, 采购公告{len(procurement_announcements)}条...", file=sys.stderr)
    for item in procurement_results:
        detail = fetch_detail(item["id"])
        if detail and detail.get("annoText"):
            item["winner"] = extract_winner(detail["annoText"])
            item["price"] = extract_price(detail["annoText"])
        else:
            item["winner"] = "-"
            item["price"] = "-"
        print(f"  结果: {clean_title(item.get('annoName',''))[:30]} → 厂商={item.get('winner','-')} 价格={item.get('price','-')}", file=sys.stderr)

    for item in procurement_announcements:
        detail = fetch_detail(item["id"])
        if detail and detail.get("annoText"):
            item["price"] = extract_price(detail["annoText"])
        else:
            item["price"] = "-"
        print(f"  公告: {clean_title(item.get('annoName',''))[:30]} → 价格={item.get('price','-')}", file=sys.stderr)

    # ===== 构建输出 =====
    header = f"## 📡 中国联通标讯日报\n**数据范围:** {cutoff_date} ~ {today} | **来源:** chinaunicombidding.cn"

    # 采购结果表格（无预算列）
    result_lines = []
    if procurement_results:
        result_lines.append(f"**📊 采购结果（{len(procurement_results)}条）**")
        result_lines.append("| 序号 | 省份 | 项目名称 | 中标厂商 | 详情 |")
        result_lines.append("|------|------|----------|----------|------|")
        for i, item in enumerate(procurement_results, 1):
            p = item.get("inferredProvince", "其他")
            n = clean_title(item.get("annoName", ""))
            w = item.get("winner", "-")
            link = DETAIL_PAGE + item["id"]
            result_lines.append(f"| {i} | {p} | {n} | {w} | [详情]({link}) |")
        result_lines.append("")

    # 采购公告表格
    announcement_lines = []
    if procurement_announcements:
        announcement_lines.append(f"**📊 采购公告（{len(procurement_announcements)}条）**")
        announcement_lines.append("| 序号 | 省份 | 项目名称 | 最高限价/预算 | 详情 |")
        announcement_lines.append("|------|------|----------|--------------|------|")
        for i, item in enumerate(procurement_announcements, 1):
            p = item.get("inferredProvince", "其他")
            n = clean_title(item.get("annoName", ""))
            pr = item.get("price", "-")
            link = DETAIL_PAGE + item["id"]
            announcement_lines.append(f"| {i} | {p} | {n} | {pr} | [详情]({link}) |")
        announcement_lines.append("")

    summary = f"---\n合计: 采购结果{len(procurement_results)}条 | 采购公告{len(procurement_announcements)}条"

    print(header + "\n")
    if result_lines:
        print("\n".join(result_lines))
    if announcement_lines:
        print("\n".join(announcement_lines))
    print(summary)


if __name__ == "__main__":
    main()
