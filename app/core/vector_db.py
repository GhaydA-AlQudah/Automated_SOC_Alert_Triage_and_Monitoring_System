# app/core/vector_db.py

import os
from typing import Any, Dict

import chromadb

from logger import logger


class SOCVectorDB:
    """
    SOC-focused Vector Database manager.

    Responsibilities:
        - Store contextual security knowledge such as policies and playbooks.
        - Index summarized historical security incidents.
        - Retrieve semantically similar security context for the AI agent.

    Design Note:
        Raw telemetry logs should not be stored directly in the Vector DB.
        PostgreSQL remains responsible for operational alert data, while
        ChromaDB acts as the semantic knowledge layer used by the AI agent.

    Stored knowledge may include:
        - Historical incident summaries.
        - Security policies.
        - Incident response playbooks.
        - Network and asset context.
        - Security-related organizational knowledge.
    """

    def __init__(self, db_path: str = "./chroma_db"):
        """
        Initialize the persistent ChromaDB client and security knowledge
        collection.

        Args:
            db_path:
                Local filesystem path used by ChromaDB for persistent storage.
                Defaults to './chroma_db'.
        """

        # Ensure the local storage directory exists before
        # initializing the persistent ChromaDB client.
        os.makedirs(db_path, exist_ok=True)

        # Create or connect to the persistent ChromaDB instance.
        self.client = chromadb.PersistentClient(path=db_path)

        # Reuse the existing collection if it already exists.
        # Otherwise, ChromaDB creates it automatically.
        self.collection = self.client.get_or_create_collection(
            name="soc_security_knowledge"
        )

        logger.info(
            f"✅ SOC Vector DB initialized successfully. "
            f"Storage: {db_path} | Collection: soc_security_knowledge"
        )

    # =================================================================
    # 1. HISTORICAL INCIDENTS STORAGE
    # =================================================================

    def add_incident_summary(
        self,
        incident_id: str,
        summary_text: str,
        metadata: Dict[str, Any],
    ) -> None:
        """
        Store a summarized historical security incident in the Vector DB.

        ChromaDB automatically generates the embedding for `summary_text`
        when the document is added to the collection.

        This method is intended for semantic security knowledge and
        historical experiences rather than raw telemetry.

        Suitable examples include:
            - Historical brute-force attacks.
            - Previous port scans.
            - Data exfiltration incidents.
            - Known malicious campaigns.
            - Previously observed false-positive patterns.

        Args:
            incident_id:
                Unique identifier for the historical incident.

            summary_text:
                Human-readable summary describing the incident behavior.

            metadata:
                Structured attributes associated with the incident.
                Example:
                    {
                        "attack_type": "Brute-Force",
                        "severity": "High",
                        "year": 2026
                    }

        Returns:
            None
        """

        logger.info(
            f"📥 Indexing historical incident into Vector DB: {incident_id}"
        )

        # Store the incident narrative and its metadata.
        # ChromaDB handles the document embedding internally.
        self.collection.add(
            ids=[incident_id],
            documents=[summary_text],
            metadatas=[metadata],
        )

        logger.info(
            f"✅ Historical incident indexed successfully: {incident_id}"
        )

    # =================================================================
    # 2. SECURITY KNOWLEDGE INGESTION
    # =================================================================

    def add_security_knowledge(
        self,
        doc_id: str,
        document_text: str,
        metadata: Dict[str, Any],
    ) -> None:
        """
        Index organizational security knowledge into the Vector DB.

        Supported knowledge categories include:

            1. Enterprise Policies
                Organizational security rules and compliance requirements.

            2. Incident Response Playbooks
                Recommended procedures for handling specific attack types.

            3. Network and Asset Context
                Infrastructure information, asset criticality, and
                organizational network context.

        Examples:

            Enterprise Policy:
                "Public-facing applications must block SQL injection
                patterns such as UNION SELECT and OR 1=1."

            Incident Playbook:
                "For an active brute-force attack, block the source IP,
                verify affected accounts, and review authentication logs."

            Network Context:
                "Server 10.0.0.5 is the primary Active Directory Domain
                Controller and is classified as a crown-jewel asset."

        Args:
            doc_id:
                Unique identifier for the knowledge document.

            document_text:
                Textual content containing the security knowledge.

            metadata:
                Structured information describing the document.

        Returns:
            None
        """

        knowledge_type = metadata.get("knowledge_type", "General")

        logger.info(
            f"📚 Indexing security knowledge: "
            f"id={doc_id} | type={knowledge_type}"
        )

        # Store the security knowledge document and associated metadata.
        # ChromaDB automatically handles document embeddings.
        self.collection.add(
            ids=[doc_id],
            documents=[document_text],
            metadatas=[metadata],
        )

        logger.info(
            f"✅ Security knowledge indexed successfully: {doc_id}"
        )

    # =================================================================
    # 3. SEMANTIC CONTEXT RETRIEVAL
    # =================================================================

    def query_similar_incidents(
        self,
        query_text: str,
        n_results: int = 3,
    ) -> Dict[str, Any]:
        """
        Retrieve semantically similar security knowledge from ChromaDB.

        The supplied query text is embedded by ChromaDB and compared
        against the embeddings stored in the collection.

        Retrieved context can include:
            - Similar historical incidents.
            - Relevant enterprise policies.
            - Applicable incident response playbooks.
            - Network and asset context.
            - Previously observed security patterns.

        This method forms the retrieval component of the RAG pipeline.

        Args:
            query_text:
                Current alert behavior, suspicious pattern, or security
                context that should be used for semantic retrieval.

            n_results:
                Maximum number of similar documents to retrieve.
                Defaults to 3.

        Returns:
            A ChromaDB result dictionary containing:
                - documents
                - metadatas
                - distances
                - ids
        """

        logger.info(
            f"🔍 Performing semantic security context search. "
            f"Requested results: {n_results}"
        )

        # ChromaDB embeds the query internally and performs
        # semantic similarity search against stored documents.
        results = self.collection.query(
            query_texts=[query_text],
            n_results=n_results,
        )

        logger.info(
            f"🔎 Retrieved {n_results} security context document(s) "
            f"from Vector DB."
        )

        return results

    # =================================================================
    # 4. COLLECTION METRICS
    # =================================================================

    def get_total_documents(self) -> int:
        """
        Return the total number of documents stored in the collection.

        Returns:
            int:
                Number of indexed security knowledge documents.
        """

        # Query ChromaDB for the current collection size.
        count = self.collection.count()

        logger.info(
            f"📦 SOC Vector DB document count: {count}"
        )

        return count


# =====================================================================
# GLOBAL SHARED VECTOR DB INSTANCE
# =====================================================================
#
# A single shared instance is used across the application.
#
# This prevents unnecessary ChromaDB client initialization in different
# modules and ensures that all components access the same persistent
# security knowledge collection.
# =====================================================================

soc_vdb = SOCVectorDB()