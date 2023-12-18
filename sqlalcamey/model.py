from sqlalchemy import Column, Integer, String, Date, ForeignKey, Boolean, Float, Text
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import Session

Base = declarative_base()


class Artifact(Base):
    """
    SQLAlchemy model class that represents the Artifact table.

    Attributes:
        __tablename__ (str): The name of the table this class represents.
        artifact_id (sqlalchemy.sql.schema.Column): The primary key column of the table.
        type_id (sqlalchemy.sql.schema.Column): Foreign key column referencing the artifact_types table.
        owner_id (sqlalchemy.sql.schema.Column): Foreign key column referencing the Organization table.
        name (sqlalchemy.sql.schema.Column): Column for the name of the artifact.
        location (sqlalchemy.sql.schema.Column): Column for the primary location of the artifact.
        secondary_location (sqlalchemy.sql.schema.Column): Column for the secondary location of the artifact.
        created_at (sqlalchemy.sql.schema.Column): Column for the creation date of the artifact.
        raw_data (sqlalchemy.sql.schema.Column): Column for the raw data of the artifact.
    """

    __tablename__ = "Artifact"

    artifact_id = Column(Integer, primary_key=True)
    type_id = Column(Integer, ForeignKey("artifact_types.artifact_type_id"))
    owner_id = Column(Integer, ForeignKey("Organization.organization_id"))
    name = Column(String)
    location = Column(String)
    secondary_location = Column(String)
    created_at = Column(Date)
    raw_data = Column(Text)


class Benchmarks(Base):
    """
    SQLAlchemy model class that represents the Benchmarks table.

    Attributes:
        __tablename__ (str): The name of the table this class represents.
        benchmark_id (sqlalchemy.sql.schema.Column): The primary key column of the table.
        version (sqlalchemy.sql.schema.Column): Column for the version of the benchmark.
        release (sqlalchemy.sql.schema.Column): Column for the release of the benchmark.
        release_date (sqlalchemy.sql.schema.Column): Column for the release date of the benchmark.
        type_id (sqlalchemy.sql.schema.Column): Foreign key column referencing the benchmark_type table.
        product_id (sqlalchemy.sql.schema.Column): Foreign key column referencing the Products table.
        author_id (sqlalchemy.sql.schema.Column): Foreign key column referencing the Organization table.
        sponsor_id (sqlalchemy.sql.schema.Column): Foreign key column referencing the Organization table.
        status_id (sqlalchemy.sql.schema.Column): Foreign key column referencing the Statuses table.
    """

    __tablename__ = "Benchmarks"

    benchmark_id = Column(Integer, primary_key=True)
    version = Column(Integer)
    release = Column(Integer)
    release_date = Column(Date)
    type_id = Column(Integer, ForeignKey("benchmark_type.benchmark_type_id"))
    product_id = Column(Integer, ForeignKey("Products.product_id"))
    author_id = Column(Integer, ForeignKey("Organization.organization_id"))
    sponsor_id = Column(Integer, ForeignKey("Organization.organization_id"))
    status_id = Column(Integer, ForeignKey("Statuses.status_id"))


class Organization(Base):
    """
    SQLAlchemy model class that represents the Organization table.

    Attributes:
        __tablename__ (str): The name of the table this class represents.
        organization_id (sqlalchemy.sql.schema.Column): The primary key column of the table.
        long_name (sqlalchemy.sql.schema.Column): Column for the long name of the organization.
        short_name (sqlalchemy.sql.schema.Column): Column for the short name of the organization.
        uri (sqlalchemy.sql.schema.Column): Column for the URI of the organization.
    """

    __tablename__ = "Organization"

    organization_id = Column(Integer, primary_key=True)
    long_name = Column(String)
    short_name = Column(String)
    uri = Column(String)
    email = Column(String)


class Products(Base):
    """
    SQLAlchemy model class that represents the Products table.

    Attributes:
        __tablename__ (str): The name of the table this class represents.
        product_id (sqlalchemy.sql.schema.Column): The primary key column of the table.
        long_name (sqlalchemy.sql.schema.Column): Column for the long name of the product.
        short_name (sqlalchemy.sql.schema.Column): Column for the short name of the product.
        version (sqlalchemy.sql.schema.Column): Column for the version of the product.
        release (sqlalchemy.sql.schema.Column): Column for the release of the product.
        owner_id (sqlalchemy.sql.schema.Column): Foreign key column referencing the Organization table.
    """

    __tablename__ = "Products"

    product_id = Column(Integer, primary_key=True)
    long_name = Column(String)
    short_name = Column(String)
    version = Column(Float)
    release = Column(Integer)
    owner_id = Column(Integer, ForeignKey("Organization.organization_id"))


class Statuses(Base):
    """
    Represents the 'Statuses' table in the database.

    The 'Statuses' table contains information about the different statuses that a benchmark can have.

    Attributes:
        status_id (Integer): The unique identifier for the status. This is the primary key in the table.
        name (String): The name of the status.
    """

    __tablename__ = "Statuses"

    status_id = Column(Integer, primary_key=True)
    name = Column(String)


class ArtifactTypes(Base):
    """
    SQLAlchemy model class that represents the artifact_types table.

    Attributes:
        __tablename__ (str): The name of the table this class represents.
        artifact_type_id (sqlalchemy.sql.schema.Column): The primary key column of the table.
        type_name (sqlalchemy.sql.schema.Column): Column for the name of the artifact type.
        description (sqlalchemy.sql.schema.Column): Column for the description of the artifact type.
    """

    __tablename__ = "artifact_types"

    artifact_type_id = Column(Integer, primary_key=True)
    type_name = Column(String)
    description = Column(Text)


class BenchmarkArtifacts(Base):
    """
    SQLAlchemy model class that represents the benchmark_artifacts table.

    Attributes:
        __tablename__ (str): The name of the table this class represents.
        benchmark_id (sqlalchemy.sql.schema.Column): Foreign key column referencing the Benchmarks table, part of the composite primary key.
        artifact_id (sqlalchemy.sql.schema.Column): Foreign key column referencing the Artifact table, part of the composite primary key.
        is_default (sqlalchemy.sql.schema.Column): Column indicating if the artifact is the default one for the benchmark.
    """

    __tablename__ = "benchmark_artifacts"

    benchmark_id = Column(
        Integer, ForeignKey("Benchmarks.benchmark_id"), primary_key=True
    )
    artifact_id = Column(Integer, ForeignKey("Artifact.artifact_id"), primary_key=True)
    is_default = Column(Boolean)


class BenchmarkType(Base):
    """
    SQLAlchemy model class that represents the benchmark_type table.

    Attributes:
        __tablename__ (str): The name of the table this class represents.
        benchmark_type_id (sqlalchemy.sql.schema.Column): The primary key column of the table.
        long_name (sqlalchemy.sql.schema.Column): Column for the long name of the benchmark type.
        short_name (sqlalchemy.sql.schema.Column): Column for the short name of the benchmark type.
        description (sqlalchemy.sql.schema.Column): Column for the description of the benchmark type.
    """

    __tablename__ = "benchmark_type"

    benchmark_type_id = Column(Integer, primary_key=True)
    long_name = Column(String)
    short_name = Column(String)
    description = Column(Text)
