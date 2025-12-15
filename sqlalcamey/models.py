from sqlalchemy import Column,Integer,String,Date,ForeignKey
from sqlalchemy import Boolean, Float, LargeBinary, UniqueConstraint

from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()


# TODO: Add indexes to the correct tables in both this interface and the SQL
class Artifact(Base):
    """
    The Artifact class represents the Artifact table in the database.

    Attributes:
        artifact_id (int): The primary key for this table.
        type_id (int): A foreign key that refers to the artifact_type_id in the artifact_types table.
        owner_id (int): A foreign key that refers to the organization_id in the Organization table.
        name (str): The name of the artifact. This field is required.
        location (str): The location of the artifact. This field is required.
        secondary_location (str): The secondary location of the artifact. This field is optional.
        created_at (date): The date when the artifact was created. This field is required.
        raw_data (LargeBinary): The raw data of the artifact. This field is optional.

    Relationships:
        artifact_type: A relationship to the ArtifactType model object associated with this artifact.
        organization: A relationship to the Organization model object associated with this artifact.
    """

    def __repr__(self):
        """
        Returns a string representation of this Artifact.

        Returns:
            str: A string representation of this Artifact.
        """
        return f"<Artifact(name={self.name}, location={self.location})>"

    __tablename__ = "Artifact"

    artifact_id = Column(Integer, primary_key=True, autoincrement=True)
    type_id = Column(Integer, ForeignKey("artifact_types.artifact_type_id"), nullable=False)
    owner_id = Column(Integer, ForeignKey("Organization.organization_id"), nullable=False)
    name = Column(String, nullable=False)
    location = Column(String, nullable=False)
    secondary_location = Column(String)
    created_at = Column(Date, nullable=False)
    raw_data = Column(LargeBinary)

    # Define relationships
    artifact_type = relationship("ArtifactType", back_populates="artifacts")
    organization = relationship("Organization", back_populates="artifacts")


class Benchmarks(Base):
    """
    The Benchmarks class represents the Benchmarks table in the database.

    Attributes:
        benchmark_id (int): The primary key for this table.
        version (int): The version of the benchmark. This field is required.
        release (int): The release number of the benchmark. This field is required.
        release_date (date): The date when the benchmark was released. This field is required.
        type_id (int): A foreign key that refers to the benchmark_type_id in the benchmark_type table. This field is required.
        product_id (int): A foreign key that refers to the product_id in the Products table. This field is required.
        author_id (int): A foreign key that refers to the organization_id in the Organization table. This field is required and defaults to 0.
        sponsor_id (int): A foreign key that refers to the organization_id in the Organization table. This field defaults to 0.
        status_id (int): A foreign key that refers to the status_id in the Statuses table. This field is required.

    Relationships:
        benchmark_type: A relationship to the BenchmarkType model object associated with this benchmark.
        product: A relationship to the Product model object associated with this benchmark.
        author: A relationship to the Organization model object that authored this benchmark.
        sponsor: A relationship to the Organization model object that sponsored this benchmark.
        status: A relationship to the Status model object associated with this benchmark.
    """

    __tablename__ = "Benchmarks"

    benchmark_id = Column(Integer, primary_key=True, autoincrement=True)
    version = Column(Integer, nullable=False)
    release = Column(Integer, nullable=False)
    release_date = Column(Date, nullable=False)
    type_id = Column(Integer, ForeignKey("benchmark_type.benchmark_type_id"), nullable=False)
    product_id = Column(Integer, ForeignKey("Products.product_id"), nullable=False)
    author_id = Column(Integer, ForeignKey("Organization.organization_id"), nullable=False, default=0)
    sponsor_id = Column(Integer, ForeignKey("Organization.organization_id"), default=0)
    status_id = Column(Integer, ForeignKey("Statuses.status_id"), nullable=False)

    # Define relationships
    benchmark_type = relationship("BenchmarkType", back_populates="benchmarks")
    product = relationship("Product", back_populates="benchmarks")
    author = relationship("Organization", back_populates="authored_benchmarks")
    sponsor = relationship("Organization", back_populates="sponsored_benchmarks")
    status = relationship("Status", back_populates="benchmarks")

    __table_args__ = (
        UniqueConstraint(
            "version",
            "release",
            "product_id",
            "author_id",
            name="unique_product_version_release_owner",
        ),
    )

    def __repr__(self):
        """
        Returns a string representation of this Benchmarks.

        Returns:
            str: A string representation of this Benchmarks.
        """
        return f"<Benchmarks(product={self.product_id}, version={self.version}, release={self.release})>"


class Organization(Base):
    """
    The Organization class represents the Organization table in the database.

    Attributes:
        organization_id (int): The primary key for this table.
        long_name (str): The full name of the organization. This field is required.
        short_name (str): The abbreviated name of the organization. This field is required.
        uri (str): The URI of the organization. This field is optional.
        email (str): The email of the organization. This field is optional.

    Constraints:
        UniqueConstraint: Ensures that the combination of long_name and short_name is unique across all organizations.

    """

    __tablename__ = "Organization"

    organization_id = Column(Integer, primary_key=True, autoincrement=True)
    long_name = Column(String, nullable=False)
    short_name = Column(String, nullable=False)
    uri = Column(String)
    email = Column(String)

    __table_args__ = (UniqueConstraint("long_name", "short_name", name="unique_org_short_and_long_name"),)

    def __repr__(self):
        """
        Returns a string representation of this Organization.

        Returns:
            str: A string representation of this Organization.
        """
        return f"<Organization(long_name={self.long_name}, short_name={self.short_name})>"


class Products(Base):
    """
    The Products class represents the Products table in the database.

    Attributes:
        product_id (int): The primary key for this table.
        long_name (str): The full name of the product. This field is required.
        short_name (str): The abbreviated name of the product. This field is required.
        version (float): The version number of the product. This field is required.
        release (int): The release number of the product. This field is required.
        owner_id (int): A foreign key that refers to the organization_id in the Organization table. This field is required.

    Relationships:
        owner: A relationship to the Organization model object that owns this product.
    """

    __tablename__ = "Products"

    product_id = Column(Integer, primary_key=True, autoincrement=True)
    long_name = Column(String, nullable=False)
    short_name = Column(String, nullable=False)
    version = Column(Float, nullable=False)
    release = Column(Integer, nullable=False)
    owner_id = Column(Integer, ForeignKey("Organization.organization_id"), nullable=False)

    # Define relationships
    owner = relationship("Organization", back_populates="products")

    def __repr__(self):
        """
        Returns a string representation of this Products.

        Returns:
            str: A string representation of this Products.
        """
        return f"<Products(long_name={self.long_name}, short_name={self.short_name})>"


class Statuses(Base):
    """
    The Statuses class represents the Statuses table in the database.

    Attributes:
        status_id (int): The primary key for this table.
        name (str): The name of the status. This field is required.

    Constraints:
        UniqueConstraint: Ensures that the combination of status_id and name is unique across all statuses.
    """

    __tablename__ = "Statuses"

    status_id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String, nullable=False)

    __table_args__ = (UniqueConstraint("status_id", "name", name="unique_status_id_name"),)

    def __repr__(self):
        """
        Returns a string representation of this Statuses.

        Returns:
            str: A string representation of this Statuses.
        """
        return f"<Statuses(status_id={self.status_id}, name={self.name})>"


class ArtifactTypes(Base):
    """
    The ArtifactTypes class represents the ArtifactTypes table in the database.

    Attributes:
        artifact_type_id (int): The primary key for this table.
        type_name (str): The name of the artifact type. This field is required.
        description (str): The description of the artifact type. This field is optional.

    """

    __tablename__ = "artifact_types"

    artifact_type_id = Column(Integer, primary_key=True, autoincrement=True)
    type_name = Column(String, nullable=False)
    description = Column(String)

    def __repr__(self):
        """
        Returns a string representation of this ArtifactTypes.

        Returns:
            str: A string representation of this ArtifactTypes.
        """
        return f"<ArtifactTypes(type_name={self.type_name}, description={self.description})>"


class BenchmarkArtifacts(Base):
    """
    The BenchmarkArtifacts class represents the BenchmarkArtifacts table in the database.

    Attributes:
        benchmark_id (int): A foreign key that refers to the benchmark_id in the Benchmarks table. This field is part of the primary key for this table.
        artifact_id (int): A foreign key that refers to the artifact_id in the Artifact table. This field is part of the primary key for this table.
        is_default (bool): A flag indicating whether this artifact is the default for the associated benchmark. This field defaults to False.

    Constraints:
        UniqueConstraint: Ensures that the combination of benchmark_id, artifact_id, and is_default is unique across all benchmark artifacts.
    """

    __tablename__ = "benchmark_artifacts"

    benchmark_id = Column(Integer, ForeignKey("Benchmarks.benchmark_id"), primary_key=True)
    artifact_id = Column(Integer, ForeignKey("Artifact.artifact_id"), primary_key=True)
    is_default = Column(Boolean, default=False)

    __table_args__ = (
        UniqueConstraint(
            "benchmark_id",
            "artifact_id",
            "is_default",
            name="unique_benchmark_artificat_default",
        ),
    )

    def __repr__(self):
        """
        Returns a string representation of this BenchmarkArtifacts.

        Returns:
            str: A string representation of this BenchmarkArtifacts.
        """
        return f"<BenchmarkArtifacts(benchmark_id={self.benchmark_id}, artifact_id={self.artifact_id})>"


class BenchmarkType(Base):
    """
    The BenchmarkType class represents the BenchmarkType table in the database.

    Attributes:
        benchmark_type_id (int): The primary key for this table.
        long_name (str): The full name of the benchmark type. This field is required.
        short_name (str): The abbreviated name of the benchmark type. This field is required.
        description (str): The description of the benchmark type. This field is required.

    Constraints:
        UniqueConstraint: Ensures that the long_name and short_name are unique across all benchmark types.
    """

    __tablename__ = "benchmark_type"

    benchmark_type_id = Column(Integer, primary_key=True, autoincrement=True)
    long_name = Column(String, nullable=False)
    short_name = Column(String, nullable=False)
    description = Column(String, nullable=False)

    __table_args__ = (
        UniqueConstraint("long_name", name="unique_bt_long_name"),
        UniqueConstraint("short_name", name="unique_bt_short_name"),
    )

    def __repr__(self):
        """
        Returns a string representation of this BenchmarkType.

        Returns:
            str: A string representation of this BenchmarkType.
        """
        return f"<BenchmarkType(long_name={self.long_name}, short_name={self.short_name})>"
