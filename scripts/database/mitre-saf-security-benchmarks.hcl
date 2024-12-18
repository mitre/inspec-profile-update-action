table "Artifact" {
  schema = schema.main
  column "artifact_id" {
    null           = false
    type           = integer
    auto_increment = true
  }
  column "type_id" {
    null = false
    type = integer
  }
  column "owner_id" {
    null = false
    type = integer
  }
  column "name" {
    null = false
    type = varchar
  }
  column "location" {
    null = false
    type = varchar
  }
  column "secondary_location" {
    null = true
    type = varchar
  }
  column "created_at" {
    null = false
    type = date
  }
  column "raw_data" {
    null = true
    type = blob
  }
  primary_key {
    columns = [column.artifact_id]
  }
  foreign_key "artifact_has_a_type" {
    columns     = [column.type_id]
    ref_columns = [table.artifact_types.column.artifact_type_id]
    on_update   = CASCADE
    on_delete   = RESTRICT
  }
  foreign_key "artifact_has_a_owner" {
    columns     = [column.owner_id]
    ref_columns = [table.Organization.column.organization_id]
    on_update   = CASCADE
    on_delete   = RESTRICT
  }
}
table "Benchmarks" {
  schema = schema.main
  column "benchmark_id" {
    null           = false
    type           = integer
    auto_increment = true
  }
  column "version" {
    null = false
    type = smallint
  }
  column "release" {
    null = false
    type = smallint
  }
  column "release_date" {
    null = false
    type = date
  }
  column "type_id" {
    null = false
    type = integer
  }
  column "product_id" {
    null = false
    type = int
  }
  column "author_id" {
    null    = false
    type    = integer
    default = 0
  }
  column "sponsor_id" {
    null    = true
    type    = integer
    default = 0
  }
  column "status_id" {
    null = false
    type = integer
  }
  primary_key {
    columns = [column.benchmark_id]
  }
  foreign_key "benchmark_has_a_type" {
    columns     = [column.type_id]
    ref_columns = [table.benchmark_type.column.benchmark_type_id]
    on_update   = CASCADE
    on_delete   = RESTRICT
  }
  foreign_key "benchmark_has_a_product" {
    columns     = [column.product_id]
    ref_columns = [table.Products.column.product_id]
    on_update   = CASCADE
    on_delete   = RESTRICT
  }
  foreign_key "benchmark_has_an_author" {
    columns     = [column.author_id]
    ref_columns = [table.Organization.column.organization_id]
    on_update   = CASCADE
    on_delete   = RESTRICT
  }
  foreign_key "benmark_has_a_sponsor" {
    columns     = [column.sponsor_id]
    ref_columns = [table.Organization.column.organization_id]
    on_update   = CASCADE
    on_delete   = RESTRICT
  }
  foreign_key "benchmark_has_a_status" {
    columns     = [column.status_id]
    ref_columns = [table.Statuses.column.status_id]
    on_update   = CASCADE
    on_delete   = RESTRICT
  }
  index "unique_product_version_release_owner" {
    unique  = true
    columns = [column.version, column.release, column.product_id, column.author_id]
  }
}
table "Organization" {
  schema = schema.main
  column "organization_id" {
    null           = false
    type           = integer
    auto_increment = true
  }
  column "long_name" {
    null = false
    type = varchar
  }
  column "short_name" {
    null = false
    type = varchar
  }
  column "uri" {
    null = true
    type = varchar
  }
  column "email" {
    null = true
    type = varchar
  }
  primary_key {
    columns = [column.organization_id]
  }
  index "unique_org_short_and_long_name" {
    unique  = true
    columns = [column.long_name, column.short_name]
  }
}
table "Products" {
  schema = schema.main
  column "product_id" {
    null = false
    type = int
  }
  column "long_name" {
    null = false
    type = varchar
  }
  column "short_name" {
    null = false
    type = varchar
  }
  column "version" {
    null = false
    type = real
  }
  column "release" {
    null = false
    type = int
  }
  column "owner_id" {
    null = false
    type = integer
  }
  foreign_key "product_has_a_owner" {
    columns     = [column.owner_id]
    ref_columns = [table.Organization.column.organization_id]
    on_update   = CASCADE
    on_delete   = RESTRICT
  }
}
table "Statuses" {
  schema = schema.main
  column "status_id" {
    null           = false
    type           = integer
    auto_increment = true
  }
  column "name" {
    null = false
    type = varchar
  }
  primary_key {
    columns = [column.status_id]
  }
  index "unique_status_id_name" {
    unique  = true
    columns = [column.status_id, column.name]
  }
}
table "artifact_types" {
  schema = schema.main
  column "artifact_type_id" {
    null           = false
    type           = integer
    auto_increment = true
  }
  column "type_name" {
    null = false
    type = varchar
  }
  column "description" {
    null = true
    type = text
  }
  primary_key {
    columns = [column.artifact_type_id]
  }
}
table "benchmark_artifacts" {
  schema = schema.main
  column "benchmark_id" {
    null = false
    type = integer
  }
  column "artifact_id" {
    null = false
    type = integer
  }
  column "is_default" {
    null    = true
    type    = int2
    default = 0
  }
  primary_key {
    columns = [column.benchmark_id, column.artifact_id]
  }
  foreign_key "benchmark_has_an_artifact" {
    columns     = [column.benchmark_id]
    ref_columns = [table.Benchmarks.column.benchmark_id]
    on_update   = CASCADE
    on_delete   = CASCADE
  }
  foreign_key "artifact_belongs_to_benchmark" {
    columns     = [column.artifact_id]
    ref_columns = [table.Artifact.column.artifact_id]
    on_update   = CASCADE
    on_delete   = CASCADE
  }
  index "unique_benchmark_artificat_default" {
    unique  = true
    columns = [column.benchmark_id, column.artifact_id, column.is_default]
  }
}
table "benchmark_type" {
  schema = schema.main
  column "benchmark_type_id" {
    null           = false
    type           = integer
    auto_increment = true
  }
  column "long_name" {
    null = false
    type = varchar
  }
  column "short_name" {
    null = false
    type = varchar
  }
  column "description" {
    null = false
    type = text
  }
  primary_key {
    columns = [column.benchmark_type_id]
  }
  index "unique_bt_long_name" {
    unique  = true
    columns = [column.long_name]
  }
  index "unique_bt_short_name" {
    unique  = true
    columns = [column.short_name]
  }
}
schema "main" {
}
