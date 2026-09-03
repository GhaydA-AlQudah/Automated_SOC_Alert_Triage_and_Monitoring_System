import os
from pathlib import Path
from typing import Any, Dict, List


import chromadb

from logger import logger


# =====================================================================
# DYNAMIC ABSOLUTE PATH RESOLUTION
# =====================================================================

BASE_DIR = Path(__file__).resolve().parent.parent.parent

DEFAULT_DB_PATH = str(
    BASE_DIR / "chroma_db"
)


# =====================================================================
# SOC VECTOR DATABASE
# =====================================================================

class SOCVectorDB:
    """
    SOC Historical Knowledge Vector Database.

    Logical record structure:

        {
            "id": "...",
            "key": "...",
            "value": "..."
        }

    ChromaDB internal mapping:

        id
            -> ids

        key
            -> documents

        value
            -> metadata["value"]

    IMPORTANT:
        The logical record contains ONLY:

            id
            key
            value

        No additional metadata fields are stored.
    """

    # =================================================================
    # INITIALIZATION
    # =================================================================

    def __init__(
        self,
        db_path: str = DEFAULT_DB_PATH,
    ) -> None:

        # -------------------------------------------------------------
        # DATABASE PATH
        # -------------------------------------------------------------

        self.db_path = os.path.abspath(
            db_path
        )

        os.makedirs(
            self.db_path,
            exist_ok=True,
        )

        # -------------------------------------------------------------
        # CHROMADB CLIENT
        # -------------------------------------------------------------

        self.client = chromadb.PersistentClient(
            path=self.db_path
        )

        # -------------------------------------------------------------
        # COLLECTION
        # -------------------------------------------------------------

        self.collection = (
            self.client.get_or_create_collection(
                name="soc_historical_incidents"
            )
        )

        logger.info(
            "SOC Historical Knowledge Vector DB "
            "initialized successfully. "
            f"Storage: {self.db_path} | "
            "Collection: soc_historical_incidents"
        )

    # =================================================================
    # 1. ADD RECORD
    # =================================================================

    def add_record(
        self,
        record_id: str,
        key: str,
        value: str,
    ) -> None:
        """
        Add one historical knowledge record.

        Logical record:

            {
                "id": record_id,
                "key": key,
                "value": value
            }

        ChromaDB:

            ids       = [record_id]
            documents = [key]
            metadatas = [{"value": value}]

        No additional metadata is stored.
        """

        # -------------------------------------------------------------
        # VALIDATE ID
        # -------------------------------------------------------------

        if not isinstance(
            record_id,
            str,
        ):
            raise TypeError(
                "record_id must be a string."
            )

        if not record_id.strip():
            raise ValueError(
                "record_id must be a non-empty string."
            )

        # -------------------------------------------------------------
        # VALIDATE KEY
        # -------------------------------------------------------------

        if not isinstance(
            key,
            str,
        ):
            raise TypeError(
                "key must be a string."
            )

        if not key.strip():
            raise ValueError(
                "key must be a non-empty string."
            )

        # -------------------------------------------------------------
        # VALIDATE VALUE
        # -------------------------------------------------------------

        if not isinstance(
            value,
            str,
        ):
            raise TypeError(
                "value must be a string."
            )

        # -------------------------------------------------------------
        # CLEAN VALUES
        # -------------------------------------------------------------

        record_id = record_id.strip()
        key = key.strip()
        value = value.strip()

        # -------------------------------------------------------------
        # LOG
        # -------------------------------------------------------------

        logger.info(
            "📥 Indexing historical knowledge record: "
            f"{record_id}"
        )

        # -------------------------------------------------------------
        # INSERT
        # -------------------------------------------------------------

        self.collection.add(
            ids=[
                record_id
            ],
            documents=[
                key
            ],
            metadatas=[
                {
                    "value": value
                }
            ],
        )

        logger.info(
            "✅ Historical knowledge record "
            "indexed successfully: "
            f"{record_id}"
        )

    # =================================================================
    # 2. ADD MULTIPLE RECORDS
    # =================================================================

    def add_records(
        self,
        records: List[Dict[str, str]],
    ) -> None:
        """
        Add multiple records.

        Expected input:

            [
                {
                    "id": "pattern_1",
                    "key": "...",
                    "value": "..."
                },
                {
                    "id": "pattern_2",
                    "key": "...",
                    "value": "..."
                }
            ]

        Only id, key, and value are accepted.
        """

        if not isinstance(
            records,
            list,
        ):
            raise TypeError(
                "records must be a list."
            )

        if not records:
            logger.info(
                "No records provided for insertion."
            )
            return

        ids: List[str] = []
        documents: List[str] = []
        metadatas: List[Dict[str, str]] = []

        # -------------------------------------------------------------
        # PREPARE RECORDS
        # -------------------------------------------------------------

        for index, record in enumerate(
            records,
            start=1,
        ):

            if not isinstance(
                record,
                dict,
            ):
                raise TypeError(
                    f"Record {index} must be a dictionary."
                )

            # ---------------------------------------------------------
            # EXACT LOGICAL FIELDS
            # ---------------------------------------------------------

            record_id = record.get(
                "id"
            )

            key = record.get(
                "key"
            )

            value = record.get(
                "value"
            )

            # ---------------------------------------------------------
            # VALIDATION
            # ---------------------------------------------------------

            if not isinstance(
                record_id,
                str,
            ) or not record_id.strip():

                raise ValueError(
                    f"Record {index}: "
                    "'id' must be a non-empty string."
                )

            if not isinstance(
                key,
                str,
            ) or not key.strip():

                raise ValueError(
                    f"Record {index}: "
                    "'key' must be a non-empty string."
                )

            if not isinstance(
                value,
                str,
            ):

                raise TypeError(
                    f"Record {index}: "
                    "'value' must be a string."
                )

            # ---------------------------------------------------------
            # STORE
            # ---------------------------------------------------------

            ids.append(
                record_id.strip()
            )

            documents.append(
                key.strip()
            )

            metadatas.append(
                {
                    "value": value.strip()
                }
            )

        # -------------------------------------------------------------
        # INSERT ALL
        # -------------------------------------------------------------

        logger.info(
            f"📥 Indexing {len(ids)} historical "
            "knowledge records..."
        )

        self.collection.add(
            ids=ids,
            documents=documents,
            metadatas=metadatas,
        )

        logger.info(
            f"✅ Successfully indexed "
            f"{len(ids)} historical knowledge records."
        )

    # =================================================================
    # 3. SEARCH SIMILAR RECORDS
    # =================================================================

    def query_similar(
        self,
        query_text: str,
        n_results: int = 3,
    ) -> Dict[str, Any]:
        """
        Search historical knowledge using semantic similarity.

        ChromaDB searches the `key` because it is stored as
        the document.

        Returns the logical structure:

            {
                "ids": [
                    ["pattern_1", ...]
                ],

                "keys": [
                    ["...", ...]
                ],

                "values": [
                    ["...", ...]
                ],

                "distances": [
                    [...]
                ]
            }

        """

        # -------------------------------------------------------------
        # VALIDATE QUERY
        # -------------------------------------------------------------

        if not isinstance(
            query_text,
            str,
        ):
            raise TypeError(
                "query_text must be a string."
            )

        query_text = query_text.strip()

        # -------------------------------------------------------------
        # EMPTY QUERY
        # -------------------------------------------------------------

        if not query_text:

            return {
                "ids": [[]],
                "keys": [[]],
                "values": [[]],
                "distances": [[]],
            }

        # -------------------------------------------------------------
        # LIMIT RESULTS
        # -------------------------------------------------------------

        n_results = max(
            1,
            min(
                n_results,
                10,
            ),
        )

        # -------------------------------------------------------------
        # CHECK DATABASE
        # -------------------------------------------------------------

        total_documents = (
            self.collection.count()
        )

        if total_documents == 0:

            logger.warning(
                "⚠️ Historical Knowledge "
                "Vector DB is empty."
            )

            return {
                "ids": [[]],
                "keys": [[]],
                "values": [[]],
                "distances": [[]],
            }

        # -------------------------------------------------------------
        # DO NOT REQUEST MORE THAN AVAILABLE
        # -------------------------------------------------------------

        n_results = min(
            n_results,
            total_documents,
        )

        logger.info(
            "🔍 Searching historical knowledge. "
            f"Requested results: {n_results}"
        )

        # -------------------------------------------------------------
        # CHROMA SEARCH
        # -------------------------------------------------------------

        results = self.collection.query(
            query_texts=[
                query_text
            ],
            n_results=n_results,
        )

        # -------------------------------------------------------------
        # EXTRACT CHROMA RESULTS
        # -------------------------------------------------------------

        result_ids = results.get(
            "ids",
            [[]],
        )

        result_documents = results.get(
            "documents",
            [[]],
        )

        result_metadatas = results.get(
            "metadatas",
            [[]],
        )

        result_distances = results.get(
            "distances",
            [[]],
        )

        # -------------------------------------------------------------
        # CONVERT TO LOGICAL STRUCTURE
        # -------------------------------------------------------------

        keys: List[List[str]] = [[]]

        values: List[List[str]] = [[]]

        if result_documents:

            keys[0] = result_documents[0]

        if result_metadatas:

            for metadata in result_metadatas[0]:

                if metadata is None:

                    values[0].append(
                        ""
                    )

                else:

                    values[0].append(
                        str(
                            metadata.get(
                                "value",
                                ""
                            )
                        )
                    )

        retrieved_count = len(
            result_ids[0]
            if result_ids
            else []
        )

        logger.info(
            f"🔎 Retrieved {retrieved_count} "
            "historical knowledge record(s)."
        )

        return {
            "ids": result_ids,
            "keys": keys,
            "values": values,
            "distances": result_distances,
        }

    # =================================================================
    # 4. BACKWARD-COMPATIBILITY SEARCH
    # =================================================================

    def query_similar_alert_patterns(
        self,
        query_text: str,
        n_results: int = 3,
    ) -> Dict[str, Any]:
        """
        Backward-compatible alias.
        """

        return self.query_similar(
            query_text=query_text,
            n_results=n_results,
        )

    # =================================================================
    # 5. BACKWARD-COMPATIBILITY INCIDENT SEARCH
    # =================================================================

    def query_similar_incidents(
        self,
        query_text: str,
        n_results: int = 3,
    ) -> Dict[str, Any]:
        """
        Backward-compatible alias.
        """

        return self.query_similar(
            query_text=query_text,
            n_results=n_results,
        )

    # =================================================================
    # 6. GET TOTAL DOCUMENTS
    # =================================================================

    def get_total_documents(self) -> int:
        """
        Return total number of logical records.
        """

        count = self.collection.count()

        logger.info(
            "📦 Historical knowledge records "
            f"in Vector DB: {count}"
        )

        return count

    # =================================================================
    # 7. GET ONE RECORD
    # =================================================================

    def get_record(
        self,
        record_id: str,
    ) -> Dict[str, str] | None:
        """
        Retrieve one logical record.

        Returns:

            {
                "id": "...",
                "key": "...",
                "value": "..."
            }

        Or None if the record does not exist.
        """

        if not isinstance(
            record_id,
            str,
        ):
            raise TypeError(
                "record_id must be a string."
            )

        record_id = record_id.strip()

        if not record_id:
            return None

        results = self.collection.get(
            ids=[
                record_id
            ],
            include=[
                "documents",
                "metadatas",
            ],
        )

        ids = results.get(
            "ids",
            [],
        )

        documents = results.get(
            "documents",
            [],
        )

        metadatas = results.get(
            "metadatas",
            [],
        )

        if not ids:
            return None

        metadata = (
            metadatas[0]
            if metadatas
            else {}
        )

        return {
            "id": ids[0],
            "key": (
                documents[0]
                if documents
                else ""
            ),
            "value": str(
                metadata.get(
                    "value",
                    ""
                )
            ),
        }

    # =================================================================
    # 8. GET ALL RECORDS
    # =================================================================

    def get_all(
        self,
    ) -> List[Dict[str, str]]:
        """
        Return all records using the logical structure:

            [
                {
                    "id": "...",
                    "key": "...",
                    "value": "..."
                }
            ]

        No ChromaDB internal structure is exposed.
        """

        total_documents = (
            self.collection.count()
        )

        if total_documents == 0:

            return []

        # -------------------------------------------------------------
        # GET RECORDS
        # -------------------------------------------------------------

        results = self.collection.get(
            include=[
                "documents",
                "metadatas",
            ],
        )

        ids = results.get(
            "ids",
            [],
        )

        documents = results.get(
            "documents",
            [],
        )

        metadatas = results.get(
            "metadatas",
            [],
        )

        records: List[
            Dict[str, str]
        ] = []

        # -------------------------------------------------------------
        # BUILD LOGICAL RECORDS
        # -------------------------------------------------------------

        for index, record_id in enumerate(
            ids
        ):

            key = (
                documents[index]
                if index < len(documents)
                else ""
            )

            metadata = (
                metadatas[index]
                if index < len(metadatas)
                else {}
            )

            value = str(
                metadata.get(
                    "value",
                    ""
                )
            )

            records.append(
                {
                    "id": record_id,
                    "key": key,
                    "value": value,
                }
            )

        return records

    # =================================================================
    # 9. CLEAR COLLECTION
    # =================================================================

    def clear_all(self) -> None:
        """
        Delete all records from the Vector DB.
        """

        count = self.collection.count()

        if count == 0:

            logger.info(
                "Vector DB is already empty."
            )

            return

        # -------------------------------------------------------------
        # GET IDS ONLY
        # -------------------------------------------------------------

        results = self.collection.get(
            include=[]
        )

        ids = results.get(
            "ids",
            [],
        )

        # -------------------------------------------------------------
        # DELETE
        # -------------------------------------------------------------

        if ids:

            self.collection.delete(
                ids=ids
            )

        logger.info(
            f"🗑️ Deleted {len(ids)} "
            "historical knowledge records "
            "from Vector DB."
        )


# =====================================================================
# GLOBAL SHARED VECTOR DB INSTANCE
# =====================================================================

soc_vdb = SOCVectorDB()