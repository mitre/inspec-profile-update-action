from sqlalchemy.orm import Session
from .models import (
    BenchmarkArtifacts,
    Artifact,
    Benchmarks,
    Organization,
    Products,
    ArtifactTypes,
    BenchmarkType,
)


class SecurityGuidance:
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
            BenchmarkArtifacts: The retrieved BenchmarkArtifact, or None if no BenchmarkArtifact \\
                with the given IDs exists.
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
            BenchmarkType: The retrieved BenchmarkType, or None if no BenchmarkType \\
                with the given ID exists.

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


"""
To interact with these models:

1. One-to-Many Relationships:
- Organization to Artifact: An organization can own multiple artifacts.
- Organization to Products: An organization can own multiple products.
- Organization to Benchmarks (as author or sponsor): An organization can author or \\
    sponsor multiple benchmarks.

For these relationships, you might need functions to:

- Get all artifacts owned by an organization.
- Get all products owned by an organization.
- Get all benchmarks authored or sponsored by an organization.

2. Many-to-Many Relationships:
- Benchmarks to Artifact through BenchmarkArtifacts: A benchmark can have multiple artifacts, \\
    and an artifact can be associated with multiple benchmarks.

For this relationship, you might need functions to:

- Get all artifacts associated with a benchmark.
- Get all benchmarks associated with an artifact.
- Associate an artifact with a benchmark.
- Disassociate an artifact from a benchmark.
"""


def get_artifacts_by_organization(session: Session, organization_id: int):
    """
    Retrieves all artifacts owned by a specific organization.

    Args:
        session (sqlalchemy.orm.Session): The session object used to execute database queries.
        organization_id (int): The ID of the organization whose artifacts you want to retrieve.

    Returns:
        List[Artifact]: A list of Artifact objects owned by the organization.
        If the organization does not own any artifacts, returns an empty list.

    Example:
        from sqlalchemy.orm import Session
        # create a new session
        session = Session()
        # get all artifacts owned by the organization with ID 1
        artifacts = get_artifacts_by_organization(session, 1)
        for artifact in artifacts:
            print(artifact.name)
    """
    return session.query(Artifact).filter(Artifact.owner_id == organization_id).all()


def get_products_by_organization(session: Session, organization_id: int):
    """
    Retrieves all products owned by a specific organization.

    Args:
        session (sqlalchemy.orm.Session): The session object used to execute database queries.
        organization_id (int): The ID of the organization whose products you want to retrieve.

    Returns:
        List[Products]: A list of Products objects owned by the organization.
        If the organization does not own any products, returns an empty list.

    Example:
        from sqlalchemy.orm import Session
        # create a new session
        session = Session()
        # get all products owned by the organization with ID 1
        products = get_products_by_organization(session, 1)
        for product in products:
            print(product.name)
    """
    return session.query(Products).filter(Products.owner_id == organization_id).all()


def get_benchmarks_by_author(session: Session, author_id: int):
    """
    Retrieves all benchmarks authored by a specific organization.

    Args:
        session (sqlalchemy.orm.Session): The session object used to execute database queries.
        author_id (int): The ID of the organization whose authored benchmarks you want to retrieve.

    Returns:
        List[Benchmarks]: A list of Benchmarks objects authored by the organization.
        If the organization has not authored any benchmarks, returns an empty list.

    Example:
        from sqlalchemy.orm import Session
        # create a new session
        session = Session()
        # get all benchmarks authored by the organization with ID 1
        benchmarks = get_benchmarks_by_author(session, 1)
        for benchmark in benchmarks:
            print(benchmark.name)
    """
    return session.query(Benchmarks).filter(Benchmarks.author_id == author_id).all()


def get_benchmarks_by_sponsor(session: Session, sponsor_id: int):
    """
    Retrieves all benchmarks sponsored by a specific organization.

    Args:
        session (sqlalchemy.orm.Session): The session object used to execute database queries.
        sponsor_id (int): The ID of the organization whose sponsored benchmarks you want to retrieve.

    Returns:
        List[Benchmarks]: A list of Benchmarks objects sponsored by the organization.
        If the organization has not sponsored any benchmarks, returns an empty list.

    Example:
        from sqlalchemy.orm import Session
        # create a new session
        session = Session()
        # get all benchmarks sponsored by the organization with ID 1
        benchmarks = get_benchmarks_by_sponsor(session, 1)
        for benchmark in benchmarks:
            print(benchmark.name)
    """
    return session.query(Benchmarks).filter(Benchmarks.sponsor_id == sponsor_id).all()


def get_artifacts_by_benchmark(session: Session, benchmark_id: int):
    """
    Retrieves all artifacts associated with a specific benchmark.

    Args:
        session (sqlalchemy.orm.Session): The session object used to execute database queries.
        benchmark_id (int): The ID of the benchmark whose associated artifacts you want to retrieve.

    Returns:
        List[Artifact]: A list of Artifact objects associated with the benchmark. If the benchmark \\
            does not have any associated artifacts, returns an empty list.

    Example:
        from sqlalchemy.orm import Session
        # create a new session
        session = Session()
        # get all artifacts associated with the benchmark with ID 1
        artifacts = get_artifacts_by_benchmark(session, 1)
        for artifact in artifacts:
            print(artifact.name)
    """
    return (
        session.query(Artifact)
        .join(BenchmarkArtifacts)
        .filter(BenchmarkArtifacts.benchmark_id == benchmark_id)
        .all()
    )


def get_benchmarks_by_artifact(session: Session, artifact_id: int):
    """
    Retrieves all benchmarks associated with a specific artifact.

    Args:
        session (sqlalchemy.orm.Session): The session object used to execute database queries.
        artifact_id (int): The ID of the artifact whose associated benchmarks you want to retrieve.

    Returns:
        List[Benchmarks]: A list of Benchmarks objects associated with the artifact. If the artifact \\
            is not associated with any benchmarks, returns an empty list.

    Example:
        from sqlalchemy.orm import Session
        # create a new session
        session = Session()
        # get all benchmarks associated with the artifact with ID 1
        benchmarks = get_benchmarks_by_artifact(session, 1)
        for benchmark in benchmarks:
            print(benchmark.name)
    """
    return (
        session.query(Benchmarks)
        .join(BenchmarkArtifacts)
        .filter(BenchmarkArtifacts.artifact_id == artifact_id)
        .all()
    )


def associate_artifact_with_benchmark(
    session: Session, benchmark_id: int, artifact_id: int, is_default: bool
):
    """
    Associates an artifact with a benchmark.

    Args:
        session (sqlalchemy.orm.Session): The session object used to execute database queries.
        benchmark_id (int): The ID of the benchmark with which you want to associate the artifact.
        artifact_id (int): The ID of the artifact you want to associate with the benchmark.
        is_default (bool): A boolean indicating whether the artifact is a default artifact for the benchmark.

    Example:
        from sqlalchemy.orm import Session
        # create a new session
        session = Session()
        # associate the artifact with ID 1 with the benchmark with ID 1, and set it as a default artifact
        associate_artifact_with_benchmark(session, 1, 1, True)
    """
    association = BenchmarkArtifacts(
        benchmark_id=benchmark_id, artifact_id=artifact_id, is_default=is_default
    )
    session.add(association)
    session.commit()


def disassociate_artifact_from_benchmark(
    session: Session, benchmark_id: int, artifact_id: int
):
    """
    Disassociates an artifact from a benchmark.

    Args:
        session (sqlalchemy.orm.Session): The session object used to execute database queries.
        benchmark_id (int): The ID of the benchmark from which you want to disassociate the artifact.
        artifact_id (int): The ID of the artifact you want to disassociate from the benchmark.

    Example:
        from sqlalchemy.orm import Session
        # create a new session
        session = Session()
        # disassociate the artifact with ID 1 from the benchmark with ID 1
        disassociate_artifact_from_benchmark(session, 1, 1)
    """
    association = (
        session.query(BenchmarkArtifacts)
        .filter(
            BenchmarkArtifacts.benchmark_id == benchmark_id,
            BenchmarkArtifacts.artifact_id == artifact_id,
        )
        .first()
    )
    if association:
        session.delete(association)
        session.commit()
