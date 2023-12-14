CREATE TABLE "Organization"(
  id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
  name VARCHAR NOT NULL,
  uri VARCHAR,
  email VARCHAR,
  CONSTRAINT "Authors_ak_1" UNIQUE(name)
);

CREATE INDEX organization_index ON "Organization"(id);
  
CREATE TABLE artifact_types(type VARCHAR NOT NULL, PRIMARY KEY(type));

CREATE TABLE benchmark_type(
  type VARCHAR NOT NULL,
  description TEXT NOT NULL,
  organization_name VARCHAR NOT NULL,
  PRIMARY KEY(type),
  CONSTRAINT name_benchmark_type FOREIGN KEY (organization_name) REFERENCES "Organization" (name)
);

CREATE TABLE "Artifact"(
  id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
  name VARCHAR NOT NULL,
  location VARCHAR NOT NULL,
  type INTEGER NOT NULL,
  created_at DATE NOT NULL,
  secondary_location VARCHAR,
  raw_data BLOB,
  type VARCHAR NOT NULL,
  author_name VARCHAR NOT NULL,
  CONSTRAINT "type_Artifact" FOREIGN KEY (type) REFERENCES artifact_types (type),
  CONSTRAINT "name_Artifact" FOREIGN KEY (author_name) REFERENCES "Organization" (name)
);

CREATE TABLE "Products"(
  name VARCHAR NOT NULL,
  version REAL NOT NULL,
  author_id INT NOT NULL,
  "release" INT,
  PRIMARY KEY(name, version),
  CONSTRAINT "id_Products" FOREIGN KEY (author_id) REFERENCES "Organization" (id)
);

CREATE TABLE "Statuses"(
  id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
  name VARCHAR NOT NULL,
  CONSTRAINT "Statuses_ak_1" UNIQUE(id),
  CONSTRAINT "Statuses_ak_2" UNIQUE(name)
);

CREATE TABLE "Benchmarks"(
  id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
  version SMALLINT NOT NULL,
  "release" SMALLINT NOT NULL,
  release_date DATE NOT NULL,
  type VARCHAR NOT NULL,
  product_name VARCHAR NOT NULL,
  product_version REAL NOT NULL,
  status VARCHAR NOT NULL,
  organization_name VARCHAR NOT NULL,
  sponsor_name VARCHAR,
  CONSTRAINT type_type FOREIGN KEY (type) REFERENCES benchmark_type (type),
  CONSTRAINT "Products_Benchmarks" FOREIGN KEY (product_name, product_version) REFERENCES "Products" (name, version),
  CONSTRAINT "name_Benchmarks" FOREIGN KEY (status) REFERENCES "Statuses" (name),
  CONSTRAINT "name_Benchmarks" FOREIGN KEY (organization_name) REFERENCES "Organization" (name),
  CONSTRAINT "name_Benchmarks" FOREIGN KEY (sponsor_name) REFERENCES "Organization" (name)
);

CREATE TABLE benchmark_artifacts(
  benchmark_id INTEGER NOT NULL,
  artifact_id INTEGER NOT NULL,
  "default" INT2,
  PRIMARY KEY(benchmark_id, artifact_id),
  CONSTRAINT id_benchmark_references FOREIGN KEY (benchmark_id) REFERENCES "Benchmarks" (id),
  CONSTRAINT id_benchmark_reference FOREIGN KEY (artifact_id) REFERENCES "Artifact" (id)
);
