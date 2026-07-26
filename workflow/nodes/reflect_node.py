# 反思迭代节点
# 对比本轮新资产与全局集合，提取新增资产；判断是否继续迭代或终止

from typing import Any


def reflect_node(state: dict[str, Any]) -> dict[str, Any]:
    """
    反思节点：检查本轮是否发现新资产，决定是否继续迭代

    - 提取本轮新资产（子域名、IP、端口）
    - 与 discovered_assets 全局集合对比
    - 设置 new_asset_found 标志
    - 递增 iteration 计数
    """
    iteration = state.get("iteration", 0)
    max_iterations = state.get("max_iterations", 30)
    discovered = set(state.get("discovered_assets", []))

    # 本轮新资产
    new_subdomains = set(state.get("subdomains", [])) - discovered
    new_ips = set(state.get("ips", [])) - discovered
    new_ports = state.get("open_ports", [])

    # 将端口信息也作为资产（ip:port 格式）
    new_port_assets = {f"{p.get('ip', '')}:{p.get('port', '')}" for p in new_ports}
    new_port_assets = {a for a in new_port_assets if ":" in a}

    all_new = new_subdomains | new_ips | new_port_assets
    new_asset_found = len(all_new) > 0

    # 更新全局资产集合
    updated_discovered = list(discovered | all_new)

    messages = [
        f"[reflect] 第 {iteration + 1} 轮反思完成",
        f"[reflect] 本轮新资产: {len(all_new)} 个",
    ]

    if new_subdomains:
        messages.append(f"[reflect] 新子域名: {list(new_subdomains)[:5]}")
    if new_ips:
        messages.append(f"[reflect] 新 IP: {list(new_ips)}")

    # 判断是否达到最大迭代次数
    next_iteration = iteration + 1
    if next_iteration >= max_iterations:
        new_asset_found = False
        messages.append(f"[reflect] 已达最大迭代次数 {max_iterations}，终止")

    # 如果新资产数量过少（只有端口变化），也终止迭代
    # 避免对每个子域名都进行一轮完整扫描
    if new_asset_found and len(new_subdomains) == 0 and len(new_ips) == 0 and len(new_port_assets) <= 2:
        new_asset_found = False
        messages.append("[reflect] 新资产数量过少，终止迭代")

    return {
        "iteration": next_iteration,
        "new_asset_found": new_asset_found,
        "discovered_assets": updated_discovered,
        "messages": messages,
    }
