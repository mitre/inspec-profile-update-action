# Things to review

- https://github.com/agronholm/sqlacodegen
- https://github.com/graphql-python/graphene-sqlalchemy/tree/master/examples/flask_sqlalchemy

// """
// SQLAlchemy model class that represents the Benchmarks table.

// Attributes:
// **tablename** (str): The name of the table this class represents.
// benchmark_id (sqlalchemy.sql.schema.Column): The primary key column of the table.
// version (sqlalchemy.sql.schema.Column): Column for the version of the benchmark.
// release (sqlalchemy.sql.schema.Column): Column for the release of the benchmark.
// release_date (sqlalchemy.sql.schema.Column): Column for the release date of the benchmark.
// type_id (sqlalchemy.sql.schema.Column): Foreign key column referencing the benchmark_type table.
// product_id (sqlalchemy.sql.schema.Column): Foreign key column referencing the Products table.
// author_id (sqlalchemy.sql.schema.Column): Foreign key column referencing the Organization table.
// sponsor_id (sqlalchemy.sql.schema.Column): Foreign key column referencing the Organization table.
// status_id (sqlalchemy.sql.schema.Column): Foreign key column referencing the Statuses table.
// """

General thought is to have a static dict in the parser module with some of these known vendors/organization
products.

```json
Benchmark {
    file_name: 'U.....', < have this
    product_name:, < generated
    short_name: < have -> SHORT STIGID RHEL_8_STIG
    long_name: < have -> RedHat Enterprise Linux -> { vendor } + { product }
    vendor:, < generated
    version:, < have
    release:, < have
    release_date:, < have "<status date="2023 -09 - 13">" vs Benchmark_date ? find out how these differ
    publisher:, < adding but have
        type: -> easy identificd from multiple places, title filename etc.
            status: add to module: <status date="2023-09-13">accepted</status>
}
```

```json
Organization {
    short_name < have this usually in the header || or 'Fixme systle value'
    long_name < added later after processs-- > default to 'fixme style value'
    ...
}

Author {

}
```

Artifact Generation:

( each of these is a entry in the artifacts table )

- have association with a owner and a benchmark

1. XCCDF File < we got it ( automated )
2. InSpec Profile JSON ( will make automated in py somehow )


    * lazy approach - make sure saf-cli is installed and have it create JSON
      from the XCCDF-File
    * med approach -> cross compline SAF JS/TS code to PY

3. URI Location of the existing or to be made profile Stub ( github location )


    ## USER UDPATED LATER

4. originial zip file form processing

# would like to have for history and easy access

5. InSpec Profile STUBS location ( uri )


    - 1) generate single file stubs
    - 2) gendrate mulitefile stub -> tar or zip -> store the tar or zip in BLOB

https://dassum.medium.com/building-rest-apis-using-fastapi-sqlalchemy-uvicorn-8a163ccf3aa1
