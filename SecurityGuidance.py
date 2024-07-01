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

    def add_benchmark_artifact:
    
    def update_benchmark_artifact:
    
    

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


class SecurityGuidance:
    @staticmethod
    def get_column_by_id(session, Table, Column, id):
        """
        This function retrieves a specific column value for a record in a table, given the record's ID.

        Args:
            session (sqlalchemy.orm.Session): The session object used to execute database queries.
            Table (sqlalchemy.ext.declarative.api.DeclarativeMeta): The SQLAlchemy model class representing the table.
            Column (sqlalchemy.sql.schema.Column): The column in the table that you want to retrieve.
            id (int): The ID of the record you want to retrieve.

        Returns:
            Any: The value of the specified column for the record with the given ID. If no such record exists, returns None.

        Usage:
            from sqlalchemy.orm import Session
            # create a new session
            session = Session()
            # get the name of the status with ID 1
            name = SecurityGuidanceUtils.get_column_by_id(session, Statuses, Statuses.name, 1)
            print(name)
        """
        result = session.query(Column).filter(Table.status_id == id).first()
        if result is not None:
            return result[0]
        else:
            return None
        
    @staticmethod
    def add_benchmark_artifact(session, benchmark_id, artifact_id, is_default):
        """
        Adds a new benchmark artifact to the benchmark_artifacts table.

        Args:
            session (sqlalchemy.orm.Session): The session object used to execute database queries.
            benchmark_id (int): The ID of the benchmark.
            artifact_id (int): The ID of the artifact.
            is_default (bool): Whether the artifact is the default one for the benchmark.

        Returns:
            None
        """
        new_benchmark_artifact = BenchmarkArtifacts(benchmark_id=benchmark_id, artifact_id=artifact_id, is_default=is_default)
        session.add(new_benchmark_artifact)
        session.commit()

    @staticmethod
    def update_benchmark_artifact(session, benchmark_id, artifact_id, is_default):
        """
        Updates an existing benchmark artifact in the benchmark_artifacts table.

        Args:
            session (sqlalchemy.orm.Session): The session object used to execute database queries.
            benchmark_id (int): The ID of the benchmark.
            artifact_id (int): The ID of the artifact.
            is_default (bool): Whether the artifact is the default one for the benchmark.

        Returns:
            None
        """
        benchmark_artifact = session.query(BenchmarkArtifacts).filter_by(benchmark_id=benchmark_id, artifact_id=artifact_id).first()
        if benchmark_artifact is not None:
            benchmark_artifact.is_default = is_default
            session.commit()
    
    @staticmethod
    def create_artifact(session: Session, type_id: int, owner_id: int, name: str, location: str, secondary_location: str, created_at: date, raw_data: str):
        """
        Creates a new Artifact and adds it to the database.

        Args:
            session (Session): The session to use for database operations.
            type_id (int): The ID of the artifact type.
            owner_id (int): The ID of the owner of the artifact.
            name (str): The name of the artifact.
            location (str): The primary location of the artifact.
            secondary_location (str): The secondary location of the artifact.
            created_at (date): The date the artifact was created.
            raw_data (str): The raw data of the artifact.

        Returns:
            None
        """
        artifact = Artifact(type_id=type_id, owner_id=owner_id, name=name, location=location, secondary_location=secondary_location, created_at=created_at, raw_data=raw_data)
        session.add(artifact)
        session.commit()

    def get_artifact_by_id(session: Session, artifact_id: int):
        """
        Retrieves an Artifact from the database by its ID.

        Args:
            session (Session): The session to use for database operations.
            artifact_id (int): The ID of the artifact to retrieve.

        Returns:
            Artifact: The retrieved Artifact, or None if no Artifact with the given ID exists.
        """
        return session.query(Artifact).filter(Artifact.artifact_id == artifact_id).first()

    def create_benchmark(session: Session, version: int, release: int, release_date: date, type_id: int, product_id: int, author_id: int, sponsor_id: int, status_id: int):
        """
        Creates a new Benchmark and adds it to the database.

        Args:
            session (Session): The session to use for database operations.
            version (int): The version of the benchmark.
            release (int): The release of the benchmark.
            release_date (date): The release date of the benchmark.
            type_id (int): The ID of the benchmark type.
            product_id (int): The ID of the product associated with the benchmark.
            author_id (int): The ID of the author of the benchmark.
            sponsor_id (int): The ID of the sponsor of the benchmark.
            status_id (int): The ID of the status of the benchmark.

        Returns:
            None
        """
        benchmark = Benchmarks(version=version, release=release, release_date=release_date, type_id=type_id, product_id=product_id, author_id=author_id, sponsor_id=sponsor_id, status_id=status_id)
        session.add(benchmark)
        session.commit()

    def get_benchmark_by_id(session: Session, benchmark_id: int):
        """
        Retrieves a Benchmark from the database by its ID.

        Args:
            session (Session): The session to use for database operations.
            benchmark_id (int): The ID of the benchmark to retrieve.

        Returns:
            Benchmarks: The retrieved Benchmark, or None if no Benchmark with the given ID exists.
        """
        return session.query(Benchmarks).filter(Benchmarks.benchmark_id == benchmark_id).first()

    def create_organization(session: Session, long_name: str, short_name: str, uri: str, email: str):
        """
        Creates a new Organization and adds it to the database.

        Args:
            session (Session): The session to use for database operations.
            long_name (str): The long name of the organization.
            short_name (str): The short name of the organization.
            uri (str): The URI of the organization.
            email (str): The email of the organization.

        Returns:
            None
        """
        organization = Organization(long_name=long_name, short_name=short_name, uri=uri, email=email)
        session.add(organization)
        session.commit()

    def get_organization_by_id(session: Session, organization_id: int):
        """
        Retrieves an Organization from the database by its ID.

        Args:
            session (Session): The session to use for database operations.
            organization_id (int): The ID of the organization to retrieve.

        Returns:
            Organization: The retrieved Organization, or None if no Organization with the given ID exists.
        """
        return session.query(Organization).filter(Organization.organization_id == organization_id).first()

    def create_product(session: Session, long_name: str, short_name: str, version: float, release: int, owner_id: int):
        """
        Creates a new Product and adds it to the database.

        Args:
            session (Session): The session to use for database operations.
            long_name (str): The long name of the product.
            short_name (str): The short name of the product.
            version (float): The version of the product.
            release (int): The release of the product.
            owner_id (int): The ID of the owner of the product.

        Returns:
            None
        """
        product = Products(long_name=long_name, short_name=short_name, version=version, release=release, owner_id=owner_id)
        session.add(product)
        session.commit()

    def get_product_by_id(session: Session, product_id: int):
        """
        Retrieves a Product from the database by its ID.

        Args:
            session (Session): The session to use for database operations.
            product_id (int): The ID of the product to retrieve.

        Returns:
            Products: The retrieved Product, or None if no Product with the given ID exists.
        """
        return session.query(Products).filter(Products.product_id == product_id).first()

    def create_artifact_type(session: Session, type_name: str, description: str):
        """
        Creates a new ArtifactType and adds it to the database.

        Args:
            session (Session): The session to use for database operations.
            type_name (str): The name of the artifact type.
            description (str): The description of the artifact type.

        Returns:
            None
        """
        artifact_type = ArtifactTypes(type_name=type_name, description=description)
        session.add(artifact_type)
        session.commit()

    def get_artifact_type_by_id(session: Session, artifact_type_id: int):
        """
        Retrieves an ArtifactType from the database by its ID.

        Args:
            session (Session): The session to use for database operations.
            artifact_type_id (int): The ID of the artifact type to retrieve.

        Returns:
            ArtifactTypes: The retrieved ArtifactType, or None if no ArtifactType with the given ID exists.
        """
        return session.query(ArtifactTypes).filter(ArtifactTypes.artifact_type_id == artifact_type_id).first()

    def create_benchmark_artifact(session: Session, benchmark_id: int, artifact_id: int, is_default: bool):
        """
        Creates a new BenchmarkArtifact and adds it to the database.

        Args:
            session (Session): The session to use for database operations.
            benchmark_id (int): The ID of the benchmark.
            artifact_id (int): The ID of the artifact.
            is_default (bool): Whether the artifact is the default one for the benchmark.

        Returns:
            None
        """
        benchmark_artifact = BenchmarkArtifacts(benchmark_id=benchmark_id, artifact_id=artifact_id, is_default=is_default)
        session.add(benchmark_artifact)
        session.commit()

    def get_benchmark_artifact_by_ids(session: Session, benchmark_id: int, artifact_id: int):
        """
        Retrieves a BenchmarkArtifact from the database by its benchmark and artifact IDs.

        Args:
            session (Session): The session to use for database operations.
            benchmark_id (int): The ID of the benchmark.
            artifact_id (int): The ID of the artifact.

        Returns:
            BenchmarkArtifacts: The retrieved BenchmarkArtifact, or None if no BenchmarkArtifact with the given IDs exists.
        """
        return session.query(BenchmarkArtifacts).filter(BenchmarkArtifacts.benchmark_id == benchmark_id, BenchmarkArtifacts.artifact_id == artifact_id).first()

    def create_benchmark_type(session: Session, long_name: str, short_name: str, description: str):
        """
        Creates a new BenchmarkType and adds it to the database.

        Args:
            session (Session): The session to use for database operations.
            long_name (str): The long name of the benchmark type.
            short_name (str): The short name of the benchmark type.
            description (str): The description of the benchmark type.

        Returns:
            None
        """
        benchmark_type = BenchmarkType(long_name=long_name, short_name=short_name, description=description)
        session.add(benchmark_type)
        session.commit()

    def get_benchmark_type_by_id(session: Session, benchmark_type_id: int):
        """
        Retrieves a BenchmarkType from the database by its ID.

        Args:
            session (Session): The session to use for database operations.
            benchmark_type_id (int): The ID of the benchmark type to retrieve.

        Returns:
            BenchmarkType: The retrieved BenchmarkType, or None if no BenchmarkType with the given ID exists.
        
        Usage:
            from sqlalchemy.orm import Session
            from models import BenchmarkType
            
            session = Session()
            benchmark_type_id = 1
            benchmark_type = get_benchmark_type_by_id(session, benchmark_type_id)
            if benchmark_type is not None:
                print(f"Retrieved benchmark type: {benchmark_type.long_name}")
            else:
                print("No benchmark type found with the given ID.")
        """
        return session.query(BenchmarkType).filter(BenchmarkType.benchmark_type_id == benchmark_type_id).first()
