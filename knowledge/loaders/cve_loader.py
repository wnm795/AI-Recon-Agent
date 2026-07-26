# CVE 数据加载模块
# 负责 CVE 漏洞数据的解析、预处理与向量库入库操作

import re
from typing import Any

from knowledge.vector_store import get_vector_store


# CPE 2.3 格式解析正则
# 示例: cpe:2.3:a:apache:http_server:2.4.51:*:*:*:*:*:*:*
CPE_REGEX = re.compile(
    r"^cpe:2\.3:([^:]+):([^:]+):([^:]+):([^:]+)"
)


def _extract_english_description(descriptions: list[dict[str, str]]) -> str:
    """从 NVD 多语言描述中提取英文描述"""
    for desc in descriptions:
        if desc.get("lang") == "en":
            return desc.get("value", "")
    # 兜底：返回第一条
    return descriptions[0].get("value", "") if descriptions else ""


def _extract_cvss_info(metrics: dict[str, Any]) -> dict[str, Any]:
    """从 metrics 中提取 CVSS 分数和等级"""
    result = {"score": 0.0, "severity": "UNKNOWN", "vector": ""}

    # 优先使用 CVSS v3.x
    for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        metric_list = metrics.get(key, [])
        if metric_list:
            metric = metric_list[0].get("cvssData", {})
            result["score"] = metric.get("baseScore", 0.0)
            result["severity"] = metric.get("baseSeverity", "UNKNOWN")
            result["vector"] = metric.get("vectorString", "")
            break

    return result


def _parse_cpe_configs(configurations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    解析 CPE 配置，提取受影响的 (vendor, product, version_range)

    返回:
        [
            {
                "vendor": "apache",
                "product": "http_server",
                "version_start": "",
                "version_start_including": False,
                "version_end": "2.4.51",
                "version_end_including": True,
            }
        ]
    """
    parsed = []
    for config in configurations:
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                criteria = match.get("criteria", "")
                m = CPE_REGEX.match(criteria)
                if not m:
                    continue

                part, vendor, product, version = m.groups()
                if part != "a":  # 只关注 applications
                    continue

                entry = {
                    "vendor": vendor.lower(),
                    "product": product.lower(),
                    "version_start": match.get("versionStartIncluding", "") or match.get("versionStartExcluding", ""),
                    "version_start_including": bool(match.get("versionStartIncluding")),
                    "version_end": match.get("versionEndIncluding", "") or match.get("versionEndExcluding", ""),
                    "version_end_including": bool(match.get("versionEndIncluding")),
                    "vulnerable": match.get("vulnerable", True),
                }
                parsed.append(entry)

    return parsed


def parse_cve(cve_raw: dict[str, Any]) -> dict[str, Any] | None:
    """
    解析单个 CVE 原始数据为结构化记录

    Args:
        cve_raw: NVD API 返回的 vulnerabilities[].cve

    Returns:
        结构化的 CVE 记录，解析失败返回 None
    """
    cve_id = cve_raw.get("id", "")
    if not cve_id:
        return None

    descriptions = cve_raw.get("descriptions", [])
    description = _extract_english_description(descriptions)

    metrics = cve_raw.get("metrics", {})
    cvss = _extract_cvss_info(metrics)

    configurations = cve_raw.get("configurations", [])
    cpe_configs = _parse_cpe_configs(configurations)

    references = cve_raw.get("references", [])
    urls = [ref.get("url", "") for ref in references if ref.get("url")]

    published = cve_raw.get("published", "")
    last_modified = cve_raw.get("lastModified", "")

    # 构建用于向量检索的文本
    vendor_products = [f"{c['vendor']} {c['product']}" for c in cpe_configs]
    search_text = f"{cve_id} {', '.join(vendor_products)} {description}".strip()

    return {
        "cve_id": cve_id,
        "description": description,
        "severity": cvss["severity"],
        "cvss_score": cvss["score"],
        "cvss_vector": cvss["vector"],
        "cpe_configs": cpe_configs,
        "references": urls,
        "published": published,
        "last_modified": last_modified,
        "search_text": search_text,
    }


def _get_embedding_function() -> Any:
    """获取 Chroma 默认 embedding function（离线可用）"""
    try:
        from chromadb.utils.embedding_functions import SentenceTransformerEmbeddingFunction
        return SentenceTransformerEmbeddingFunction(model_name="all-MiniLM-L6-v2")
    except Exception:
        # 如果无法加载 sentence-transformers，使用 Chroma 默认 embedding
        return None


def get_cve_collection():
    """获取 CVE 知识库集合"""
    client = get_vector_store()
    embedding_func = _get_embedding_function()
    if embedding_func:
        return client.get_or_create_collection(
            name="cve_knowledge",
            embedding_function=embedding_func,
        )
    return client.get_or_create_collection(name="cve_knowledge")


def load_cves_to_vector_store(cve_records: list[dict[str, Any]]) -> int:
    """
    将 CVE 记录批量写入 Chroma 向量库

    Args:
        cve_records: parse_cve 返回的记录列表

    Returns:
        成功写入的记录数
    """
    collection = get_cve_collection()

    ids = []
    documents = []
    metadatas = []

    for record in cve_records:
        if not record:
            continue

        cve_id = record["cve_id"]
        ids.append(cve_id)
        documents.append(record["search_text"])

        # Chroma metadata 不支持嵌套 dict/list，需要序列化复杂字段
        import json
        metadata = {
            "cve_id": record["cve_id"],
            "description": record["description"][:2000],  # 限制长度
            "severity": record["severity"],
            "cvss_score": float(record["cvss_score"]),
            "cvss_vector": record["cvss_vector"],
            "published": record["published"],
            "last_modified": record["last_modified"],
            "references": json.dumps(record["references"][:10]),
            "cpe_configs": json.dumps(record["cpe_configs"]),
        }
        metadatas.append(metadata)

    if not ids:
        return 0

    # 分批写入，避免单次过大
    batch_size = 500
    total = 0
    for i in range(0, len(ids), batch_size):
        batch_ids = ids[i:i + batch_size]
        batch_docs = documents[i:i + batch_size]
        batch_metas = metadatas[i:i + batch_size]
        collection.upsert(
            ids=batch_ids,
            documents=batch_docs,
            metadatas=batch_metas,
        )
        total += len(batch_ids)

    return total


def search_cves(
    query: str,
    top_k: int = 10,
    filters: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """
    从向量库中检索与查询相关的 CVE

    Args:
        query: 查询文本，如 "nginx 1.18.0 vulnerability"
        top_k: 返回条数
        filters: Chroma where 过滤条件，如 {"severity": {"$eq": "CRITICAL"}}

    Returns:
        CVE 记录列表
    """
    collection = get_cve_collection()

    try:
        results = collection.query(
            query_texts=[query],
            n_results=top_k,
            where=filters,
        )
    except Exception as e:
        print(f"[cve_loader] 向量库查询失败: {e}")
        return []

    import json
    cves = []
    metadatas = results.get("metadatas", [[]])[0]
    distances = results.get("distances", [[]])[0]

    for meta, distance in zip(metadatas, distances):
        if not meta:
            continue
        try:
            cve = {
                "cve_id": meta.get("cve_id", ""),
                "description": meta.get("description", ""),
                "severity": meta.get("severity", "UNKNOWN"),
                "cvss_score": meta.get("cvss_score", 0.0),
                "cvss_vector": meta.get("cvss_vector", ""),
                "published": meta.get("published", ""),
                "last_modified": meta.get("last_modified", ""),
                "references": json.loads(meta.get("references", "[]")),
                "cpe_configs": json.loads(meta.get("cpe_configs", "[]")),
                "distance": distance,
            }
            cves.append(cve)
        except Exception:
            continue

    return cves


def get_cve_count() -> int:
    """获取向量库中 CVE 记录总数"""
    try:
        collection = get_cve_collection()
        return collection.count()
    except Exception:
        return 0
