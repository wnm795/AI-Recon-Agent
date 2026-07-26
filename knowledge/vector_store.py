# Chroma 向量库封装模块
# 强制注入 Embedding，提供在线/离线双方案；管理 cve_knowledge、fingerprint_rules、port_service 三个集合

import chromadb
from chromadb.config import Settings


def get_vector_store():
    """
    获取 Chroma 向量库实例

    返回已初始化的 ChromaDB 客户端
    """
    from config.settings import CHROMA_DB_PATH

    client = chromadb.PersistentClient(
        path=str(CHROMA_DB_PATH),
        settings=Settings(
            anonymized_telemetry=False,
        ),
    )

    # 确保集合存在
    for collection_name in ["cve_knowledge", "fingerprint_rules", "port_service"]:
        client.get_or_create_collection(name=collection_name)

    return client
