# BenchmarkRepository.py
from datetime import date
from sqlalchemy.orm import Session
from SecurityGuidance import Benchmarks
from .models import BenchmarkStatus


class BenchmarksRepository:
    """
    A repository providing an interface for accessing and manipulating Benchmarks in the database.

    Attributes:
        session (Session): The SQLAlchemy session for database operations.

    Methods:
        get_benchmark_by_id(benchmark_id: int): Retrieve a benchmark by its ID.
        add_benchmark(version: int, release: int, release_date: date, type_id: int, product_id: int, author_id: int, sponsor_id: int, status_id: int): Add a new benchmark to the database.
        update_benchmark(benchmark_id: int, version: int, release: int, release_date: date, type_id: int, product_id: int, author_id: int, sponsor_id: int, status_id: int): Update an existing benchmark in the database.
        remove_benchmark(benchmark_id: int): Remove an existing benchmark from the database.
        get_all_benchmarks(): Retrieve all benchmarks from the database.
    """

    def __init__(self, session: Session):
        """
        Initialize a new BenchmarksRepository.

        Args:
            session (Session): The SQLAlchemy session to use for database operations.

        Usage:
            # First, create a new SQLAlchemy session
            from sqlalchemy import create_engine
            from sqlalchemy.orm import sessionmaker

            engine = create_engine('sqlite:///benchmarks.db')
            Session = sessionmaker(bind=engine)
            session = Session()

            # Then, create a new instance of BenchmarksRepository using the session
            repo = BenchmarksRepository(session)
        """
        self.session = session

    def add_benchmark(
        self,
        version: int,
        release: int,
        release_date: date,
        type_id: int,
        product_id: int,
        author_id: int,
        status_id: int,
        sponsor_id: int = None,
    ):
        """
        Add a new benchmark to the database.

        Args:
            version (int): The version of the benchmark.
            release (int): The release of the benchmark.
            release_date (date): The release date of the benchmark.
            type_id (int): The type ID of the benchmark.
            product_id (int): The product ID of the benchmark.
            author_id (int): The author ID of the benchmark.
            status_id (int): The status ID of the benchmark.
            sponsor_id (int, optional): The sponsor ID of the benchmark. Defaults to None.

        Returns:
            Benchmarks: The newly created benchmark.

        Usage:
            # Create a new instance of BenchmarksRepository
            repo = BenchmarksRepository(session)

            # Add a new benchmark
            new_benchmark = repo.add_benchmark(
                version=1,
                release=1,
                release_date=date.today(),
                type_id=1,
                product_id=1,
                author_id=1,
                status_id=1,
            )

            print(f"Added new benchmark with ID {new_benchmark.benchmark_id}")
        """
        new_benchmark = Benchmarks(
            version=version,
            release=release,
            release_date=release_date,
            type_id=type_id,
            product_id=product_id,
            author_id=author_id,
            sponsor_id=sponsor_id,
            status_id=status_id,
        )
        self.session.add(new_benchmark)
        self.session.commit()
        return new_benchmark

    def get_benchmark_by_id(self, benchmark_id: int):
        """
        Retrieve a benchmark by its ID.

        Args:
            benchmark_id (int): The ID of the benchmark to retrieve.

        Returns:
            Benchmarks: The retrieved benchmark, or None if no benchmark with the given ID exists.

        Usage:
            # Create a new instance of BenchmarksRepository
            repo = BenchmarksRepository(session)

            # Get a benchmark with ID 1
            benchmark = repo.get_benchmark_by_id(1)

            if benchmark is not None:
                print(f"Retrieved benchmark with ID {benchmark.benchmark_id}")
            else:
                print("No benchmark found with the given ID")
        """
        return (
            self.session.query(Benchmarks)
            .filter(Benchmarks.benchmark_id == benchmark_id)
            .first()
        )

    def get_all_benchmarks(self):
        """
        Retrieve all benchmarks from the database.

        Returns:
            List[Benchmarks]: A list of all benchmarks.

        Usage:
            # Create a new instance of BenchmarksRepository
            repo = BenchmarksRepository(session)

            # Get all benchmarks
            all_benchmarks = repo.get_all_benchmarks()

            for benchmark in all_benchmarks:
                print(f"Benchmark ID: {benchmark.benchmark_id}")
        """
        return self.session.query(Benchmarks).all()

    def update_benchmark(
        self,
        benchmark_id: int,
        version: int,
        release: int,
        release_date: date,
        type_id: int,
        product_id: int,
        author_id: int,
        status_id: int,
        sponsor_id: int = None,
    ):
        """
        Update an existing benchmark in the database.

        Args:
            benchmark_id (int): The ID of the benchmark to update.
            version (int): The new version of the benchmark.
            release (int): The new release of the benchmark.
            release_date (date): The new release date of the benchmark.
            type_id (int): The new type ID of the benchmark.
            product_id (int): The new product ID of the benchmark.
            author_id (int): The new author ID of the benchmark.
            sponsor_id (int, optional): The new sponsor ID of the benchmark. Defaults to None.
            status_id (int): The new status ID of the benchmark.

        Returns:
            Benchmarks: The updated benchmark, or None if no benchmark with the given ID exists.

        Usage:
            # Create a new instance of BenchmarksRepository
            repo = BenchmarksRepository(session)

            # Update a benchmark with ID 1
            updated_benchmark = repo.update_benchmark(
                benchmark_id=1,
                version=1,
                release=2,
                release_date=date.today(),
                type_id=1,
                product_id=1,
                author_id=1,
                sponsor_id=1,
                status_id=1,
            )

            if updated_benchmark is not None:
                print(f"Updated benchmark with ID {updated_benchmark.benchmark_id}")
            else:
                print("No benchmark found with the given ID")
        """
        benchmark = self.get_benchmark_by_id(benchmark_id)
        if benchmark is None:
            return None  # or you might raise an exception

        attributes = {
            "version": version,
            "release": release,
            "release_date": release_date,
            "type_id": type_id,
            "product_id": product_id,
            "author_id": author_id,
            "status_id": status_id,
            "sponsor_id": sponsor_id,
        }

        for attr, value in attributes.items():
            if value is not None:
                setattr(benchmark, attr, value)

        self.session.commit()
        return benchmark

    def remove_benchmark_by_id(self, benchmark_id: int):
        """
        Remove an existing benchmark from the database.

        Args:
            benchmark_id_by_id (benchmark_id: int): The ID of the benchmark to remove.

        Returns:
            bool: True if the benchmark was removed, False otherwise.

        Usage:
            # Create a new instance of BenchmarksRepository
            repo = BenchmarksRepository(session)

            # Remove a benchmark with ID 1
            if repo.remove_benchmark(benchmark_id=1):
                print("Benchmark removed successfully")
            else:
                print("No benchmark found with the given ID")
        """
        benchmark = self.get_benchmark_by_id(benchmark_id)
        if benchmark is None:
            return False

        self.session.delete(benchmark)
        self.session.commit()
        return True


class BenchmarkStatusRepository:
    def __init__(self, session):
        """
        Initialize a new BenchmarkStatusRepository.

        Args:
            session (Session): The SQLAlchemy session to use for database operations.
        """
        self.session = session

    def get_status_by_id(self, status_id: int):
        """
        Retrieve a benchmark status by its ID.

        Args:
            status_id (int): The ID of the benchmark status to retrieve.

        Returns:
            BenchmarkStatus: The benchmark status with the given ID, or None if no such benchmark status exists.
        """
        return self.session.query(BenchmarkStatus).get(status_id)

    def add_status(self, name: str):
        """
        Add a new benchmark status to the database.

        Args:
            name (str): The name of the benchmark status.

        Returns:
            BenchmarkStatus: The newly created benchmark status.
        """
        new_status = BenchmarkStatus(name=name)
        self.session.add(new_status)
        self.session.commit()
        return new_status

    def update_status(self, status_id: int, name: str):
        """
        Update an existing benchmark status in the database.

        Args:
            status_id (int): The ID of the benchmark status to update.
            name (str): The new name of the benchmark status.

        Returns:
            BenchmarkStatus: The updated benchmark status, or None if no benchmark status with the given ID exists.
        """
        status = self.session.query(BenchmarkStatus).get(status_id)
        if status is not None:
            status.name = name
            self.session.commit()
        return status

    def remove_status(self, status_id: int):
        """
        Remove an existing benchmark status from the database.

        Args:
            status_id (int): The ID of the benchmark status to remove.

        Returns:
            bool: True if the benchmark status was removed, False otherwise.
        """
        status = self.session.query(BenchmarkStatus).get(status_id)
        if status is not None:
            self.session.delete(status)
            self.session.commit()
            return True
        return False

    def get_all_statuses(self):
        """
        Retrieve all benchmark statuses from the database.

        Returns:
            List[BenchmarkStatus]: A list of all benchmark statuses.
        """
        return self.session.query(BenchmarkStatus).all()


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
        new_benchmark_artifact = BenchmarkArtifacts(
            benchmark_id=benchmark_id, artifact_id=artifact_id, is_default=is_default
        )
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
        benchmark_artifact = (
            session.query(BenchmarkArtifacts)
            .filter_by(benchmark_id=benchmark_id, artifact_id=artifact_id)
            .first()
        )
        if benchmark_artifact is not None:
            benchmark_artifact.is_default = is_default
            session.commit()

    @staticmethod
    def create_artifact(
        session: Session,
        type_id: int,
        owner_id: int,
        name: str,
        location: str,
        secondary_location: str,
        created_at: date,
        raw_data: str,
    ):
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
        artifact = Artifact(
            type_id=type_id,
            owner_id=owner_id,
            name=name,
            location=location,
            secondary_location=secondary_location,
            created_at=created_at,
            raw_data=raw_data,
        )
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
        return (
            session.query(Artifact).filter(Artifact.artifact_id == artifact_id).first()
        )

    def create_benchmark(
        session: Session,
        version: int,
        release: int,
        release_date: date,
        type_id: int,
        product_id: int,
        author_id: int,
        sponsor_id: int,
        status_id: int,
    ):
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
        benchmark = Benchmarks(
            version=version,
            release=release,
            release_date=release_date,
            type_id=type_id,
            product_id=product_id,
            author_id=author_id,
            sponsor_id=sponsor_id,
            status_id=status_id,
        )
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
        return (
            session.query(Benchmarks)
            .filter(Benchmarks.benchmark_id == benchmark_id)
            .first()
        )

    def create_organization(
        session: Session, long_name: str, short_name: str, uri: str, email: str
    ):
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
        organization = Organization(
            long_name=long_name, short_name=short_name, uri=uri, email=email
        )
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
        return (
            session.query(Organization)
            .filter(Organization.organization_id == organization_id)
            .first()
        )

    def create_product(
        session: Session,
        long_name: str,
        short_name: str,
        version: float,
        release: int,
        owner_id: int,
    ):
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
        product = Products(
            long_name=long_name,
            short_name=short_name,
            version=version,
            release=release,
            owner_id=owner_id,
        )
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
        return (
            session.query(ArtifactTypes)
            .filter(ArtifactTypes.artifact_type_id == artifact_type_id)
            .first()
        )

    def create_benchmark_artifact(
        session: Session, benchmark_id: int, artifact_id: int, is_default: bool
    ):
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
        benchmark_artifact = BenchmarkArtifacts(
            benchmark_id=benchmark_id, artifact_id=artifact_id, is_default=is_default
        )
        session.add(benchmark_artifact)
        session.commit()

    def get_benchmark_artifact_by_ids(
        session: Session, benchmark_id: int, artifact_id: int
    ):
        """
        Retrieves a BenchmarkArtifact from the database by its benchmark and artifact IDs.

        Args:
            session (Session): The session to use for database operations.
            benchmark_id (int): The ID of the benchmark.
            artifact_id (int): The ID of the artifact.

        Returns:
            BenchmarkArtifacts: The retrieved BenchmarkArtifact, or None if no BenchmarkArtifact with the given IDs exists.
        """
        return (
            session.query(BenchmarkArtifacts)
            .filter(
                BenchmarkArtifacts.benchmark_id == benchmark_id,
                BenchmarkArtifacts.artifact_id == artifact_id,
            )
            .first()
        )

    def create_benchmark_type(
        session: Session, long_name: str, short_name: str, description: str
    ):
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
        benchmark_type = BenchmarkType(
            long_name=long_name, short_name=short_name, description=description
        )
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
        return (
            session.query(BenchmarkType)
            .filter(BenchmarkType.benchmark_type_id == benchmark_type_id)
            .first()
        )


class ArtifactsRepository:
    pass
