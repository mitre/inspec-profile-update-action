CREATE TABLE "Artifact"(
  artifact_id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
  type_id INTEGER NOT NULL,
  owner_id INTEGER NOT NULL,
  name VARCHAR NOT NULL,
  location VARCHAR NOT NULL,
  secondary_location VARCHAR,
  created_at DATE NOT NULL,
  raw_data BLOB,
  CONSTRAINT artifact_has_a_type FOREIGN KEY (type_id) REFERENCES artifact_types (artifact_type_id) ON DELETE Restrict ON UPDATE Cascade,
  CONSTRAINT artifact_has_a_owner FOREIGN KEY (owner_id) REFERENCES "Organization" (organization_id) ON DELETE Restrict ON UPDATE Cascade
);

CREATE TABLE "Benchmarks"(
  benchmark_id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
  version SMALLINT NOT NULL,
  "release" SMALLINT NOT NULL,
  release_date DATE NOT NULL,
  type_id INTEGER NOT NULL,
  product_id INT NOT NULL,
  author_id INTEGER NOT NULL DEFAULT 0,
  sponsor_id INTEGER DEFAULT 0,
  status_id INTEGER NOT NULL,
  CONSTRAINT benchmark_has_a_type FOREIGN KEY (type_id) REFERENCES benchmark_type (benchmark_type_id) ON DELETE Restrict ON UPDATE Cascade,
  CONSTRAINT benchmark_has_a_product FOREIGN KEY (product_id) REFERENCES "Products" (product_id) ON DELETE Restrict ON UPDATE Cascade,
  CONSTRAINT benchmark_has_an_author FOREIGN KEY (author_id) REFERENCES "Organization" (organization_id) ON DELETE Restrict ON UPDATE Cascade,
  CONSTRAINT benmark_has_a_sponsor FOREIGN KEY (sponsor_id) REFERENCES "Organization" (organization_id) ON DELETE Restrict ON UPDATE Cascade,
  CONSTRAINT benchmark_has_a_status FOREIGN KEY (status_id) REFERENCES "Statuses" (status_id) ON DELETE Restrict ON UPDATE Cascade
);

  CREATE UNIQUE INDEX unique_product_version_release_owner ON "Benchmarks"(
    version,
    "release",
    product_id,
    author_id
  );
  
  
CREATE TABLE "Organization"(
  organization_id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
  long_name VARCHAR NOT NULL,
  short_name VARCHAR NOT NULL,
  uri VARCHAR,
  email VARCHAR
);

  CREATE UNIQUE INDEX unique_org_short_and_long_name ON "Organization"(long_name, short_name);
  
CREATE TABLE "Products"(
  product_id INT NOT NULL,
  long_name VARCHAR NOT NULL,
  short_name VARCHAR NOT NULL,
  version REAL NOT NULL,
  "release" INT NOT NULL,
  owner_id INTEGER NOT NULL,
  CONSTRAINT product_has_a_owner FOREIGN KEY (owner_id) REFERENCES "Organization" (organization_id) ON DELETE Restrict ON UPDATE Cascade
);

CREATE TABLE "Statuses"(status_id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, name VARCHAR NOT NULL);

  CREATE UNIQUE INDEX unique_status_id_name ON "Statuses"(status_id, name);
  
CREATE TABLE artifact_types(
  artifact_type_id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
  type_name VARCHAR NOT NULL,
  description TEXT
);

CREATE TABLE benchmark_artifacts(
  benchmark_id INTEGER NOT NULL,
  artifact_id INTEGER NOT NULL,
  is_default INT2 DEFAULT 0,
  PRIMARY KEY(benchmark_id, artifact_id),
  CONSTRAINT benchmark_has_an_artifact FOREIGN KEY (benchmark_id) REFERENCES "Benchmarks" (benchmark_id) ON DELETE Cascade ON UPDATE Cascade,
  CONSTRAINT artifact_belongs_to_benchmark FOREIGN KEY (artifact_id) REFERENCES "Artifact" (artifact_id) ON DELETE Cascade ON UPDATE Cascade
);

  CREATE UNIQUE INDEX unique_benchmark_artificat_default ON benchmark_artifacts(
    benchmark_id,
    artifact_id,
    is_default
  );
  
  
CREATE TABLE benchmark_type(
  benchmark_type_id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
  long_name VARCHAR NOT NULL,
  short_name VARCHAR NOT NULL,
  description TEXT NOT NULL
);

  CREATE UNIQUE INDEX unique_bt_long_name ON benchmark_type(long_name);
  
  CREATE UNIQUE INDEX unique_bt_short_name ON benchmark_type(short_name);
  