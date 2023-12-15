import asyncio
import os

import libsql_client


async def main():
    url = os.getenv("URL", "file:secruity_guidance.db")
    async with libsql_client.create_client(url) as client:
        await client.batch(
            [
                """
            CREATE TABLE "Organization"(
            organization_id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
            short_name VARCHAR NOT NULL,
            uri VARCHAR,
            email VARCHAR,
            long_name VARCHAR NOT NULL
            );
            """,

            """
            CREATE TABLE artifact_types
            (type_name VARCHAR NOT NULL, artifact_type_id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, description TEXT);
            """,

            """
            CREATE TABLE benchmark_type(
            short_name VARCHAR NOT NULL,
            description TEXT NOT NULL,
            benchmark_type_id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
            long_name VARCHAR NOT NULL
            );
            """,

            """
            CREATE TABLE "Artifact"(
            artifact_id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
            name VARCHAR NOT NULL,
            location VARCHAR NOT NULL,
            created_at DATE NOT NULL,
            secondary_location VARCHAR,
            raw_data BLOB,
            type_id INTEGER NOT NULL,
            organization_id INTEGER NOT NULL,
            CONSTRAINT "type_Artifact" FOREIGN KEY (type_id) REFERENCES artifact_types (artifact_type_id),
            CONSTRAINT "organization_id_Artifact" FOREIGN KEY (organization_id) REFERENCES "Organization" (organization_id)
            );
            """,

            """
            CREATE TABLE "Products"(
            short_name VARCHAR NOT NULL,
            version REAL NOT NULL,
            author_id INT NOT NULL,
            "release" INT NOT NULL,
            long_name VARCHAR NOT NULL,
            product_id INT NOT NULL,
            organization_id INTEGER NOT NULL,
            CONSTRAINT "organization_id_Products" FOREIGN KEY (organization_id) REFERENCES "Organization" (organization_id)
            );
            """,

            """
            CREATE TABLE "Statuses"(status_id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, name VARCHAR NOT NULL);
            """,

            """
            CREATE TABLE "Benchmarks"(
            benchmark_id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
            version SMALLINT NOT NULL,
            "release" SMALLINT NOT NULL,
            release_date DATE NOT NULL,
            type_id INTEGER NOT NULL,
            product_id INT NOT NULL,
            author_id INTEGER NOT NULL,
            sponsor_id INTEGER NOT NULL,
            status_id INTEGER NOT NULL,
            CONSTRAINT "benchmark_type_id_Benchmarks" FOREIGN KEY (type_id) REFERENCES benchmark_type (benchmark_type_id),
            CONSTRAINT "product_id_Benchmarks" FOREIGN KEY (product_id) REFERENCES "Products" (product_id),
            CONSTRAINT "organization_id_Benchmarks" FOREIGN KEY (author_id) REFERENCES "Organization" (organization_id),
            CONSTRAINT "organization_id_Benchmarks" FOREIGN KEY (sponsor_id) REFERENCES "Organization" (organization_id),
            CONSTRAINT "status_id_Benchmarks" FOREIGN KEY (status_id) REFERENCES "Statuses" (status_id)
            );
            """,

            """
            CREATE TABLE benchmark_artifacts(
            "default" INT2,
            benchmark_id INTEGER NOT NULL,
            artifact_id INTEGER NOT NULL,
            PRIMARY KEY(benchmark_id, artifact_id),
            CONSTRAINT benchmark_id_benchmark_artifacts FOREIGN KEY (benchmark_id) REFERENCES "Benchmarks" (benchmark_id),
            CONSTRAINT artifact_id_benchmark_artifacts FOREIGN KEY (artifact_id) REFERENCES "Artifact" (artifact_id)
            );
            """,
            ]
        )


asyncio.run(main())