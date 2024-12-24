-- Create "Artifact" table
CREATE TABLE
    `Artifact` (
        `artifact_id` integer NOT NULL PRIMARY KEY AUTOINCREMENT,
        `type_id` integer NOT NULL,
        `owner_id` integer NOT NULL,
        `name` varchar NOT NULL,
        `location` varchar NOT NULL,
        `secondary_location` varchar NULL,
        `created_at` date NOT NULL,
        `raw_data` BLOB NULL,
        CONSTRAINT `artifact_has_a_type` FOREIGN KEY (`type_id`) REFERENCES `artifact_types` (`artifact_type_id`) ON UPDATE CASCADE ON DELETE RESTRICT,
        CONSTRAINT `artifact_has_a_owner` FOREIGN KEY (`owner_id`) REFERENCES `Organization` (`organization_id`) ON UPDATE CASCADE ON DELETE RESTRICT
    );

-- Create "Benchmarks" table
CREATE TABLE
    `Benchmarks` (
        `benchmark_id` integer NOT NULL PRIMARY KEY AUTOINCREMENT,
        `version` smallint NOT NULL,
        `release` smallint NOT NULL,
        `release_date` date NOT NULL,
        `type_id` integer NOT NULL,
        `product_id` int NOT NULL,
        `author_id` integer NOT NULL DEFAULT 0,
        `sponsor_id` integer NULL DEFAULT 0,
        `status_id` integer NOT NULL,
        CONSTRAINT `benchmark_has_a_type` FOREIGN KEY (`type_id`) REFERENCES `benchmark_type` (`benchmark_type_id`) ON UPDATE CASCADE ON DELETE RESTRICT,
        CONSTRAINT `benchmark_has_a_product` FOREIGN KEY (`product_id`) REFERENCES `Products` (`product_id`) ON UPDATE CASCADE ON DELETE RESTRICT,
        CONSTRAINT `benchmark_has_an_author` FOREIGN KEY (`author_id`) REFERENCES `Organization` (`organization_id`) ON UPDATE CASCADE ON DELETE RESTRICT,
        CONSTRAINT `benmark_has_a_sponsor` FOREIGN KEY (`sponsor_id`) REFERENCES `Organization` (`organization_id`) ON UPDATE CASCADE ON DELETE RESTRICT,
        CONSTRAINT `benchmark_has_a_status` FOREIGN KEY (`status_id`) REFERENCES `Statuses` (`status_id`) ON UPDATE CASCADE ON DELETE RESTRICT
    );

-- Create index "unique_product_version_release_owner" to table: "Benchmarks"
CREATE UNIQUE INDEX `unique_product_version_release_owner` ON `Benchmarks` (`version`, `release`, `product_id`, `author_id`);

-- Create "Organization" table
CREATE TABLE
    `Organization` (
        `organization_id` integer NOT NULL PRIMARY KEY AUTOINCREMENT,
        `long_name` varchar NOT NULL,
        `short_name` varchar NOT NULL,
        `uri` varchar NULL,
        `email` varchar NULL
    );

-- Create index "unique_org_short_and_long_name" to table: "Organization"
CREATE UNIQUE INDEX `unique_org_short_and_long_name` ON `Organization` (`long_name`, `short_name`);

-- Create "Products" table
CREATE TABLE
    `Products` (
        `product_id` integer NOT NULL PRIMARY KEY AUTOINCREMENT,
        `long_name` varchar NOT NULL,
        `short_name` varchar NOT NULL,
        `version` real NOT NULL,
        `release` int NOT NULL,
        `owner_id` integer NOT NULL,
        CONSTRAINT `product_has_a_owner` FOREIGN KEY (`owner_id`) REFERENCES `Organization` (`organization_id`) ON UPDATE CASCADE ON DELETE RESTRICT
    );

-- Create "Statuses" table
CREATE TABLE
    `Statuses` (
        `status_id` integer NOT NULL PRIMARY KEY AUTOINCREMENT,
        `name` varchar NOT NULL
    );

-- Create index "unique_status_id_name" to table: "Statuses"
CREATE UNIQUE INDEX `unique_status_id_name` ON `Statuses` (`status_id`, `name`);

-- Create "artifact_types" table
CREATE TABLE
    `artifact_types` (
        `artifact_type_id` integer NOT NULL PRIMARY KEY AUTOINCREMENT,
        `type_name` varchar NOT NULL,
        `description` text NULL
    );

-- Create "benchmark_artifacts" table
CREATE TABLE
    `benchmark_artifacts` (
        `benchmark_id` integer NOT NULL,
        `artifact_id` integer NOT NULL,
        -- this should become a BOOL if we move off sqlite
        `is_default` int2 NULL DEFAULT 0,
        PRIMARY KEY (`benchmark_id`, `artifact_id`),
        CONSTRAINT `benchmark_has_an_artifact` FOREIGN KEY (`benchmark_id`) REFERENCES `Benchmarks` (`benchmark_id`) ON UPDATE CASCADE ON DELETE CASCADE,
        CONSTRAINT `artifact_belongs_to_benchmark` FOREIGN KEY (`artifact_id`) REFERENCES `Artifact` (`artifact_id`) ON UPDATE CASCADE ON DELETE CASCADE
    );

-- Create index "unique_benchmark_artificat_default" to table: "benchmark_artifacts"
CREATE UNIQUE INDEX `unique_benchmark_artificat_default` ON `benchmark_artifacts` (`benchmark_id`, `artifact_id`, `is_default`);

-- Create "benchmark_type" table
CREATE TABLE
    `benchmark_type` (
        `benchmark_type_id` integer NOT NULL PRIMARY KEY AUTOINCREMENT,
        `long_name` varchar NOT NULL,
        `short_name` varchar NOT NULL,
        `description` text NOT NULL
    );

-- Create index "unique_bt_long_name" to table: "benchmark_type"
CREATE UNIQUE INDEX `unique_bt_long_name` ON `benchmark_type` (`long_name`);

-- Create index "unique_bt_short_name" to table: "benchmark_type"
CREATE UNIQUE INDEX `unique_bt_short_name` ON `benchmark_type` (`short_name`);

-- Create index "unique_long_short_name" on table: "benchmark_type"
CREATE UNIQUE INDEX unique_long_short_name ON `benchmark_type` (`long_name`, `short_name`);