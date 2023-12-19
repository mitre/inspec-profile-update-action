# repository.py
from datetime import date
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from .models import (
    Artifact,
    ArtifactTypes,
    Benchmarks,
    BenchmarkArtifacts,
    BenchmarkType,
    Statuses,
    BenchmarkType,
    Organization,
    Products,
)


class ArtifactRepository:
    """
    A repository for managing Artifact entities in a database.

    This class provides methods for creating, retrieving, updating, and deleting Artifact entities, as well as retrieving associated ArtifactType and Organization entities.

    Attributes:
        session (Session): The SQLAlchemy session that will be used for database operations.

    Methods:
        __init__(self, session: Session): Initialize a new instance of the ArtifactRepository class.
        get_all(self): Retrieve all Artifact entities from the database.
        get_by_id(self, artifact_id: int): Retrieve an Artifact entity by its ID.
        create(self, **kwargs): Create a new Artifact entity and save it to the database.
        update(self, artifact_id: int, **kwargs): Update an Artifact entity with the given ID.
        delete(self, artifact_id: int): Delete an Artifact entity by its ID.
        get_artifact_type(self, artifact_id: int): Retrieve the ArtifactType associated with an Artifact entity.
        get_organization(self, artifact_id: int): Retrieve the Organization associated with an Artifact entity.
        get_raw_data(self, artifact_id: int): Retrieve the raw_data of an Artifact entity by its ID.
        get_created_date(self, artifact_id: int): Retrieve the created_at date of an Artifact entity by its ID.
        update_raw_data(self, artifact_id: int, new_raw_data: bytes): Update the raw_data of an Artifact entity by its ID.
        get_artifacts_by_type(self, type_id: int): Retrieve all Artifact entities with a specific ArtifactType.
        get_artifacts_by_organization(self, organization_id: int): Retrieve all Artifact entities belonging to a specific Organization.

    Example:
        from sqlalchemy.orm import Session
        from sqlalchemy import create_engine

        engine = create_engine('sqlite:///example.db')
        Session = sessionmaker(bind=engine)
        session = Session()

        repo = ArtifactRepository(session)

        # Create a new artifact
        artifact = repo.create(name='Artifact 1', location='Location 1', created_at=date.today(), type_id=1, owner_id=1)
        print(artifact.artifact_id)  # Outputs the ID of the newly created artifact

        # Retrieve all artifacts
        artifacts = repo.get_all()
        for artifact in artifacts:
            print(artifact.name)  # Outputs the name of each artifact

        # Retrieve an artifact by ID
        artifact = repo.get_by_id(1)
        if artifact:
            print(artifact.name)  # Outputs the name of the artifact

        # Update an artifact
        repo.update(1, name='Updated Artifact')
        updated_artifact = repo.get_by_id(1)
        print(updated_artifact.name)  # Outputs 'Updated Artifact'

        # Delete an artifact
        repo.delete(1)
        deleted_artifact = repo.get_by_id(1)
        print(deleted_artifact)  # Outputs 'None'

        # Retrieve the artifact type of an artifact
        artifact_type = repo.get_artifact_type(1)
        if artifact_type:
            print(artifact_type.type_name)  # Outputs the type name of the artifact type

        # Retrieve the organization of an artifact
        organization = repo.get_organization(1)
        if organization:
            print(organization.name)  # Outputs the name of the organization

        # Retrieve the raw data of an artifact
        raw_data = repo.get_raw_data(1)
        if raw_data:
            print(raw_data)  # Outputs the raw data of the artifact

        # Retrieve the created date of an artifact
        created_date = repo.get_created_date(1)
        if created_date:
            print(created_date)  # Outputs the created date of the artifact

        # Update the raw data of an artifact
        success = repo.update_raw_data(1, b'New raw data')
        print(success)  # Outputs 'True' if the update was successful, 'False' otherwise

        # Retrieve all artifacts of a specific type
        artifacts_by_type = repo.get_artifacts_by_type(1)
        for artifact in artifacts_by_type:
            print(artifact.name)  # Outputs the name of each artifact

        # Retrieve all artifacts of a specific organization
        artifacts_by_organization = repo.get_artifacts_by_organization(1)
        for artifact in artifacts_by_organization:
            print(artifact.name)  # Outputs the name of each artifact
    """

    def __init__(self, session: Session):
        self.session = session

    def get_all(self):
        """
        Retrieve all Artifact entities from the database.

        Returns:
            list[Artifact]: A list of all Artifact entities.

        Example:
            repo = ArtifactRepository(session)
            artifacts = repo.get_all()
            for artifact in artifacts:
                print(artifact.name)  # Outputs the name of each artifact
        """
        return self.session.query(Artifact).all()

    def get_by_id(self, artifact_id: int):
        """
        Retrieve an Artifact entity by its ID.

        Args:
            artifact_id (int): The ID of the Artifact entity to retrieve.

        Returns:
            Artifact: The Artifact entity with the given ID, or None if not found.

        Example:
            repo = ArtifactRepository(session)
            artifact = repo.get_by_id(1)
            if artifact:
                print(artifact.name)  # Outputs the name of the artifact
        """
        return self.session.query(Artifact).get(artifact_id)

    def create(self, **kwargs):
        """
        Create a new Artifact entity and save it to the database.

        Args:
            **kwargs: The properties of the Artifact entity to create.
            - type_id (int): The ID of the artifact type.
            - owner_id (int): The ID of the owner of the artifact.
            - name (str): The name of the artifact.
            - location (str): The primary location of the artifact.
            - secondary_location (str): The secondary location of the artifact.
            - created_at (date): The date the artifact was created.
            - raw_data (LargeBinary): The raw data of the artifact. This field is optional.

        Returns:
            Artifact: The newly created Artifact entity.

        Example:
            repo = ArtifactRepository(session)
            artifact = repo.create(name='New Artifact', location='Location', created_at=date.today(), type_id=1, owner_id=1)
            print(artifact.artifact_id)  # Outputs the ID of the newly created artifact
        """

        # Check for invalid arguments
        valid_args = {
            "type_id",
            "owner_id",
            "name",
            "location",
            "secondary_location",
            "created_at",
            "raw_data",
        }
        if not set(kwargs.keys()).issubset(valid_args):
            print("Invalid arguments provided.")
            return None

        artifact = Artifact(**kwargs)
        try:
            self.session.add(artifact)
            self.session.commit()
            return artifact
        except Exception as e:
            print(f"Failed to create Artifact: {e}")
            self.session.rollback()
            return None

    def update(self, artifact_id: int, **kwargs):
        """
        Update an Artifact entity with the given ID.

        Args:
            artifact_id (int): The ID of the Artifact entity to update.
            **kwargs: The properties to update.

        Example:
            repo = ArtifactRepository(session)
            repo.update(1, name='Updated Artifact')  # Updates the name of the artifact with ID 1
        """
        # Check for invalid arguments
        valid_args = {
            "type_id",
            "owner_id",
            "name",
            "location",
            "secondary_location",
            "created_at",
            "raw_data",
        }
        if not set(kwargs.keys()).issubset(valid_args):
            print("Invalid arguments provided.")
            return None

        artifact = self.session.query(Artifact).get(artifact_id)
        if artifact:
            for key, value in kwargs.items():
                setattr(artifact, key, value)
            try:
                self.session.commit()
            except Exception as e:
                print(f"Failed to update Artifact: {e}")
                self.session.rollback()
                return None
        else:
            print(f"No Artifact found with ID {artifact_id}")
            return None

    def delete(self, artifact_id: int):
        """
        Delete an Artifact entity by its ID.

        Args:
            artifact_id (int): The ID of the Artifact entity to delete.

        Example:
            repo = ArtifactRepository(session)
            repo.delete(1)  # Deletes the artifact with ID 1
        """
        artifact = self.session.query(Artifact).get(artifact_id)
        if artifact:
            self.session.delete(artifact)
            self.session.commit()

    def get_artifact_type(self, artifact_id: int):
        """
        Retrieve the ArtifactType associated with an Artifact entity.

        Args:
            artifact_id (int): The ID of the Artifact entity.

        Returns:
            ArtifactType: The ArtifactType associated with the Artifact entity, or None if not found.

        Example:
            repo = ArtifactRepository(session)
            artifact_type = repo.get_artifact_type(1)
            if artifact_type:
                print(artifact_type.type_name)  # Outputs the type name of the artifact type
        """
        artifact = self.session.query(Artifact).get(artifact_id)
        return artifact.artifact_type if artifact else None

    def get_organization(self, artifact_id: int):
        """
        Retrieve the Organization associated with an Artifact entity.

        Args:
            artifact_id (int): The ID of the Artifact entity.

        Returns:
            Organization: The Organization associated with the Artifact entity, or None if not found.

        Example:
            repo = ArtifactRepository(session)
            organization = repo.get_organization(1)
            if organization:
                print(organization.name)  # Outputs the name of the organization
        """
        artifact = self.session.query(Artifact).get(artifact_id)
        return artifact.organization if artifact else None

    def get_raw_data(self, artifact_id: int):
        """
        Retrieve the raw_data of an Artifact entity by its ID.

        Args:
            artifact_id (int): The ID of the Artifact entity.

        Returns:
            bytes: The raw_data of the Artifact entity.
        """
        artifact = self.session.query(Artifact).get(artifact_id)
        if artifact:
            return artifact.raw_data
        else:
            return None

    def get_created_date(self, artifact_id: int):
        """
        Retrieve the created_at date of an Artifact entity by its ID.

        Args:
            artifact_id (int): The ID of the Artifact entity.

        Returns:
            date: The created_at date of the Artifact entity.
        """
        artifact = self.session.query(Artifact).get(artifact_id)
        if artifact:
            return artifact.created_at
        else:
            return None

    def update_raw_data(self, artifact_id: int, new_raw_data: bytes):
        """
        Update the raw_data of an Artifact entity by its ID.

        Args:
            artifact_id (int): The ID of the Artifact entity.
            new_raw_data (bytes): The new raw_data to update the Artifact entity with.

        Returns:
            bool: True if the update was successful, False otherwise.
        """
        artifact = self.session.query(Artifact).get(artifact_id)
        if artifact:
            artifact.raw_data = new_raw_data
            self.session.commit()
            return True
        else:
            return False

    def get_artifacts_by_type(self, type_id: int):
        """
        Retrieve all Artifact entities with a specific ArtifactType.

        Args:
            type_id (int): The ID of the ArtifactType.

        Returns:
            List[Artifact]: A list of Artifact entities with the specified ArtifactType.
        """
        artifacts = self.session.query(Artifact).filter(Artifact.type_id == type_id).all()
        return artifacts

    def get_artifacts_by_organization(self, organization_id: int):
        """
        Retrieve all Artifact entities belonging to a specific Organization.

        Args:
            organization_id (int): The ID of the Organization.

        Returns:
            List[Artifact]: A list of Artifact entities belonging to the specified Organization.
        """
        artifacts = self.session.query(Artifact).filter(Artifact.owner_id == organization_id).all()
        return artifacts


class BenchmarksRepository:
    """
    A repository for managing Benchmarks entities in a database.

    Attributes:
        session (Session): The SQLAlchemy session that will be used for database operations.

    Methods:
        __init__(self, session: Session): Initialize a new instance of the BenchmarksRepository class.
        get_all(self): Retrieve all Benchmarks entities from the database.
        get_by_id(self, benchmark_id: int): Retrieve a Benchmarks entity by its ID.
        create(self, **kwargs): Create a new Benchmarks entity and save it to the database.
        update(self, benchmark_id: int, **kwargs): Update a Benchmarks entity with the given ID.
        delete(self, benchmark_id: int): Delete a Benchmarks entity by its ID.
        add_product(self, benchmark_id, product_id): Associates a product with a benchmark.
        get_associated_entities(self, benchmark_id: int): Retrieve the associated entities of a Benchmarks entity.
        get_benchmarks_by_type(self, type_id): Retrieve all Benchmarks entities associated with a specific BenchmarkType.
        get_benchmarks_by_product(self, product_id): Retrieve all Benchmarks entities associated with a specific Product.
        get_benchmarks_by_author(self, author_id): Retrieve all Benchmarks entities associated with a specific author Organization.
        get_benchmarks_by_sponsor(self, sponsor_id): Retrieve all Benchmarks entities associated with a specific sponsor Organization.
        get_benchmarks_by_status(self, status_id): Retrieve all Benchmarks entities associated with a specific Status.

    Example:
        from sqlalchemy.orm import Session
        from sqlalchemy import create_engine

        engine = create_engine('sqlite:///example.db')
        Session = sessionmaker(bind=engine)
        session = Session()

        repo = BenchmarksRepository(session)

        # Create a new benchmark
        benchmark = repo.create(version='1.0', name='Benchmark 1', description='This is a benchmark.')
        print(benchmark.id)  # Outputs the ID of the newly created benchmark

        # Retrieve all benchmarks
        benchmarks = repo.get_all()
        for benchmark in benchmarks:
            print(benchmark.version)  # Outputs the version of each benchmark

        # Retrieve a benchmark by ID
        benchmark = repo.get_by_id(1)
        if benchmark:
            print(benchmark.version)  # Outputs the version of the benchmark

        # Update a benchmark
        repo.update(1, version='1.1', name='Updated Benchmark')
        updated_benchmark = repo.get_by_id(1)
        print(updated_benchmark.version)  # Outputs '1.1'
        print(updated_benchmark.name)  # Outputs 'Updated Benchmark'

        # Delete a benchmark
        repo.delete(1)
        deleted_benchmark = repo.get_by_id(1)
        print(deleted_benchmark)  # Outputs 'None'

        # Retrieve the associated entities of a benchmark
        entities = repo.get_associated_entities(1)
        print(entities)  # Outputs the associated entities

        # Retrieve all benchmarks associated with a specific BenchmarkType
        benchmarks = repo.get_benchmarks_by_type(1)
        for benchmark in benchmarks:
            print(benchmark.version)  # Outputs the version of each benchmark

        # Retrieve all benchmarks associated with a specific Product
        benchmarks = repo.get_benchmarks_by_product(1)
        for benchmark in benchmarks:
            print(benchmark.version)  # Outputs the version of each benchmark

        # Retrieve all benchmarks associated with a specific author Organization
        benchmarks = repo.get_benchmarks_by_author(1)
        for benchmark in benchmarks:
            print(benchmark.version)  # Outputs the version of each benchmark

        # Retrieve all benchmarks associated with a specific sponsor Organization
        benchmarks = repo.get_benchmarks_by_sponsor(1)
        for benchmark in benchmarks:
            print(benchmark.version)  # Outputs the version of each benchmark

        # Retrieve all benchmarks associated with a specific Status
        benchmarks = repo.get_benchmarks_by_status(1)
        for benchmark in benchmarks:
            print(benchmark.version)  # Outputs the version of each benchmark
    """

    def __init__(self, session: Session):
        """
        Initialize a new instance of the BenchmarksRepository class.

        Args:
            session (Session): The SQLAlchemy session that will be used for database operations.

        Example:
            from sqlalchemy.orm import Session
            from sqlalchemy import create_engine

            engine = create_engine('sqlite:///example.db')
            Session = sessionmaker(bind=engine)
            session = Session()

            repo = BenchmarksRepository(session)
        """
        self.session = session

    def get_all(self):
        """
        Retrieve all Benchmarks entities from the database.

        Returns:
            list[Benchmarks]: A list of all Benchmarks entities.

        Example:
            repo = BenchmarksRepository(session)
            benchmarks = repo.get_all()
            for benchmark in benchmarks:
                print(benchmark.version)  # Outputs the version of each benchmark
        """
        return self.session.query(Benchmarks).all()

    def get_by_id(self, benchmark_id: int):
        """
        Retrieve a Benchmarks entity by its ID.

        Args:
            benchmark_id (int): The ID of the Benchmarks entity to retrieve.

        Returns:
            Benchmarks: The Benchmarks entity with the given ID, or None if not found.

        Example:
            repo = BenchmarksRepository(session)
            benchmark = repo.get_by_id(1)
            if benchmark:
                print(benchmark.version)  # Outputs the version of the benchmark
        """
        return self.session.query(Benchmarks).get(benchmark_id)

    def create(
        self,
        version,
        release,
        release_date,
        type_id,
        product_id,
        author_id,
        status_id,
        sponsor_id=None,
    ):
        """
        Creates a new benchmark.

        Args:
            version (str): The version of the benchmark.
            release (str): The release of the benchmark.
            release_date (date): The release date of the benchmark.
            type_id (int): The ID of the benchmark type.
            product_id (int): The ID of the product.
            author_id (int): The ID of the authoring organization.
            status_id (int): The ID of the status.
            sponsor_id (int, optional): The ID of the sponsoring organization.

        Returns:
            Benchmark: The newly created Benchmark object.

        Raises:
            ValueError: If a benchmark with the same version, release, product_id, and author_id already exists.

        Example:
            repo = BenchmarksRepository(session)

            # Create a new benchmark
            benchmark = repo.create('1.0', 'A', date.today(), 1, 2, 3, 4, 5)

            print(benchmark.version)  # Outputs: '1.0'
        """
        new_benchmark = Benchmarks(
            version=version,
            release=release,
            release_date=release_date,
            type_id=type_id,
            product_id=product_id,
            author_id=author_id,
            status_id=status_id,
            sponsor_id=sponsor_id,
        )
        self.session.add(new_benchmark)
        try:
            self.session.commit()
            return new_benchmark
        except IntegrityError:
            self.session.rollback()
            raise ValueError("A benchmark with this version, release, product_id, and author_id already exists.")

    def update(self, benchmark_id, **kwargs):
        """
        Updates a benchmark.

        Args:
            benchmark_id (int): The ID of the benchmark to update.
            **kwargs: Arbitrary keyword arguments. Each argument represents a field to update on the benchmark.

        Returns:
            Benchmark: The updated Benchmark object, or None if no benchmark with the provided ID was found.

        Raises:
            ValueError: If updating the benchmark would result in a duplicate version, release, product_id, and author_id.

        Example:
            repo = BenchmarksRepository(session)

            # Update the version of a benchmark with ID 1
            benchmark = repo.update(1, version='1.1')

            print(benchmark.version)  # Outputs: '1.1'
        """
        benchmark = self.get_by_id(benchmark_id)
        if benchmark:
            for key, value in kwargs.items():
                setattr(benchmark, key, value)
            try:
                self.session.commit()
                return benchmark
            except IntegrityError:
                self.session.rollback()
                raise ValueError("A benchmark with this version, release, product_id, and author_id already exists.")

    def delete(self, benchmark_id: int):
        """
        Delete a Benchmarks entity by its ID.

        Args:
            benchmark_id (int): The ID of the Benchmarks entity to delete.

        Example:
            repo = BenchmarksRepository(session)
            repo.delete(1)
            deleted_benchmark = repo.get_by_id(1)
            print(deleted_benchmark)  # Outputs 'None'
        """
        benchmark = self.session.query(Benchmarks).get(benchmark_id)
        if benchmark:
            self.session.delete(benchmark)
            self.session.commit()

    def add_product(self, benchmark_id, product_id):
        """
        Associates a product with a benchmark.

        This method sets the product_id foreign key in the Benchmarks table to the provided product_id,
        effectively associating the product with the benchmark.

        Args:
            benchmark_id (int): The ID of the benchmark.
            product_id (int): The ID of the product to associate with the benchmark.

        Returns:
            Benchmark: The updated benchmark object, or None if no benchmark with the provided ID was found.

        Raises:
            IntegrityError: If the provided product_id does not exist in the Products table.

        Example:
            repo = BenchmarksRepository(session)

            # Assume we have a benchmark with ID 1 and a product with ID 2
            benchmark = repo.add_product(1, 2)

            print(benchmark.product_id)  # Outputs: 2
        """
        benchmark = self.get_by_id(benchmark_id)
        if benchmark:
            try:
                benchmark.product = product_id
                self.session.commit()
            except IntegrityError:
                self.session.rollback()
                raise ValueError("The provided product_id does not exist in the Products table.")
        return benchmark

    def get_associated_entities(self, benchmark_id: int):
        """
        Retrieve the associated entities of a Benchmark entity.

        Args:
            benchmark_id (int): The ID of the Benchmark entity.

        Returns:
            dict: A dictionary containing the associated entities.

        Example:
            repo = BenchmarksRepository(session)
            entities = repo.get_associated_entities(1)
            print(entities)  # Outputs the associated entities
        """
        benchmark = self.session.query(Benchmarks).get(benchmark_id)
        if benchmark:
            return {
                "benchmark_type": benchmark.benchmark_type,
                "product": benchmark.product,
                "author": benchmark.author,
                "sponsor": benchmark.sponsor,
                "status": benchmark.status,
            }
        return None

    def get_benchmarks_by_type(self, type_id):
        """
        Retrieves all benchmarks of a specific type.

        Args:
            type_id (int): The ID of the benchmark type.

        Returns:
            List[Benchmark]: A list of Benchmark objects with the specified type_id.

        Example:
            repo = BenchmarksRepository(session)

            # Assume we have benchmarks of type 1
            benchmarks = repo.get_benchmarks_by_type(1)

            for benchmark in benchmarks:
                print(benchmark.type_id)  # Outputs: 1
        """
        return self.session.query(Benchmarks).filter(Benchmarks.type_id == type_id).all()

    def get_benchmarks_by_product(self, product_id):
        """
        Retrieves all benchmarks for a specific product.

        Args:
            product_id (int): The ID of the product.

        Returns:
            List[Benchmark]: A list of Benchmark objects for the specified product_id.

        Example:
            repo = BenchmarksRepository(session)

            # Assume we have benchmarks for product 2
            benchmarks = repo.get_benchmarks_by_product(2)

            for benchmark in benchmarks:
                print(benchmark.product_id)  # Outputs: 2
        """
        return self.session.query(Benchmarks).filter(Benchmarks.product_id == product_id).all()

    def get_benchmarks_by_author(self, author_id):
        """
        Retrieves all benchmarks authored by a specific organization.

        Args:
            author_id (int): The ID of the authoring organization.

        Returns:
            List[Benchmark]: A list of Benchmark objects authored by the specified organization.

        Example:
            repo = BenchmarksRepository(session)

            # Assume we have benchmarks authored by organization 3
            benchmarks = repo.get_benchmarks_by_author(3)

            for benchmark in benchmarks:
                print(benchmark.author_id)  # Outputs: 3
        """
        return self.session.query(Benchmarks).filter(Benchmarks.author_id == author_id).all()

    def get_benchmarks_by_sponsor(self, sponsor_id):
        """
        Retrieves all benchmarks sponsored by a specific organization.

        Args:
            sponsor_id (int): The ID of the sponsoring organization.

        Returns:
            List[Benchmark]: A list of Benchmark objects sponsored by the specified organization.

        Example:
            repo = BenchmarksRepository(session)

            # Assume we have benchmarks sponsored by organization 4
            benchmarks = repo.get_benchmarks_by_sponsor(4)

            for benchmark in benchmarks:
                print(benchmark.sponsor_id)  # Outputs: 4
        """
        return self.session.query(Benchmarks).filter(Benchmarks.sponsor_id == sponsor_id).all()

    def get_benchmarks_by_status(self, status_id):
        """
        Retrieves all benchmarks with a specific status.

        Args:
            status_id (int): The ID of the status.

        Returns:
            List[Benchmark]: A list of Benchmark objects with the specified status_id.

        Example:
            repo = BenchmarksRepository(session)

            # Assume we have benchmarks with status 5
            benchmarks = repo.get_benchmarks_by_status(5)

            for benchmark in benchmarks:
                print(benchmark.status_id)  # Outputs: 5
        """
        return self.session.query(Benchmarks).filter(Benchmarks.status_id == status_id).all()


class StatusesRepository:
    """
    A repository for managing Statuses entities in a database.

    Attributes:
        session (Session): The SQLAlchemy session that will be used for database operations.

    Methods:
        __init__(self, session: Session): Initialize a new instance of the StatusesRepository class.
        get_all(self): Retrieve all Statuses entities from the database.
        get_by_id(self, status_id: int): Retrieve a Statuses entity by its ID.
        create(self, name: str): Create a new Statuses entity and save it to the database.
        update(self, status_id: int, name: str): Update a Statuses entity with the given ID.
        delete(self, status_id: int): Delete a Statuses entity by its ID.

    Example:
        from sqlalchemy.orm import Session
        from sqlalchemy import create_engine

        engine = create_engine('sqlite:///example.db')
        Session = sessionmaker(bind=engine)
        session = Session()

        repo = StatusesRepository(session)

        # Create a new status
        status = repo.create(name='New Status')
        print(status.status_id)  # Outputs the ID of the newly created status

        # Retrieve all statuses
        statuses = repo.get_all()
        for status in statuses:
            print(status.name)  # Outputs the name of each status

        # Retrieve a status by ID
        status = repo.get_by_id(1)
        if status:
            print(status.name)  # Outputs the name of the status

        # Update a status
        repo.update(1, name='Updated Status')
        updated_status = repo.get_by_id(1)
        print(updated_status.name)  # Outputs 'Updated Status'

        # Delete a status
        repo.delete(1)
        deleted_status = repo.get_by_id(1)
        print(deleted_status)  # Outputs 'None'
    """

    def __init__(self, session: Session):
        self.session = session

    def get_all(self):
        return self.session.query(Statuses).all()

    def get_by_id(self, status_id):
        return self.session.query(Statuses).get(status_id)

    def create(self, name):
        new_status = Statuses(name=name)
        self.session.add(new_status)
        self.session.commit()
        return new_status

    def update(self, status_id, name):
        status = self.get_by_id(status_id)
        if status:
            status.name = name
            self.session.commit()
        return status

    def delete(self, status_id):
        status = self.get_by_id(status_id)
        if status:
            self.session.delete(status)
            self.session.commit()


class OrganizationRepository:
    """
    A repository for managing Organization entities in a database.

    Attributes:
        session (Session): The SQLAlchemy session that will be used for database operations.

    Methods:
        __init__(self, session: Session): Initialize a new instance of the OrganizationRepository class.
        get_all(self): Retrieve all Organization entities from the database.
        get_by_id(self, organization_id: int): Retrieve an Organization entity by its ID.
        create(self, long_name: str, short_name: str, uri: str, email: str): Create a new Organization entity and save it to the database.
        update(self, organization_id: int, **kwargs): Update an Organization entity with the given ID.
        delete(self, organization_id: int): Delete an Organization entity by its ID.

    Example:
        from sqlalchemy.orm import Session
        from sqlalchemy import create_engine

        engine = create_engine('sqlite:///example.db')
        Session = sessionmaker(bind=engine)
        session = Session()

        repo = OrganizationRepository(session)

        # Create a new organization
        organization = repo.create(long_name='New Organization', short_name='NO', uri='http://example.com', email='info@example.com')
        print(organization.organization_id)  # Outputs the ID of the newly created organization

        # Retrieve all organizations
        organizations = repo.get_all()
        for organization in organizations:
            print(organization.long_name)  # Outputs the long_name of each organization

        # Retrieve an organization by ID
        organization = repo.get_by_id(1)
        if organization:
            print(organization.long_name)  # Outputs the long_name of the organization

        # Update an organization
        repo.update(1, long_name='Updated Organization', short_name='UO')
        updated_organization = repo.get_by_id(1)
        print(updated_organization.long_name)  # Outputs 'Updated Organization'

        # Delete an organization
        repo.delete(1)
        deleted_organization = repo.get_by_id(1)
        print(deleted_organization)  # Outputs 'None'
    """

    def __init__(self, session: Session):
        self.session = session

    def get_all(self):
        return self.session.query(Organization).all()

    def get_by_id(self, organization_id):
        return self.session.query(Organization).get(organization_id)

    def create(self, long_name, short_name, uri, email):
        new_organization = Organization(long_name=long_name, short_name=short_name, uri=uri, email=email)
        self.session.add(new_organization)
        try:
            self.session.commit()
            return new_organization
        except IntegrityError:
            self.session.rollback()
            raise ValueError("An organization with this long_name and short_name already exists.")

    def update(self, organization_id, **kwargs):
        organization = self.get_by_id(organization_id)
        if organization:
            for key, value in kwargs.items():
                setattr(organization, key, value)
            try:
                self.session.commit()
                return organization
            except IntegrityError:
                self.session.rollback()
                raise ValueError("An organization with this long_name and short_name already exists.")

    def delete(self, organization_id):
        organization = self.get_by_id(organization_id)
        if organization:
            self.session.delete(organization)
            self.session.commit()


class ProductRepository:
    """
    A repository providing an interface for accessing and manipulating Product entities in the database.

    Methods:

        __init__(self, session: Session): Initialize a new instance of the ProductRepository class.

        create(session: Session, long_name: str, short_name: str, version: float, release: int, owner_id: int) -> Products:
            Create a new entity and add it to the database.

        get_by_id(session: Session, id: int) -> Products:
            Get an entity by its ID.

        get_all(session: Session) -> list[Products]:
            Get all entities.

        update(session: Session, id: int, short_name: str, version: float, release: int, owner_id: int, long_name: str = None) -> None:
            Update an entity.

        delete(session: Session, id: int) -> None:
            Delete an entity.

    Examples:
        >>> repo = Repository()
        >>> new_entity = repo.create(session, 'Long Name', 'Short Name', 1.0, 1, 1)
        >>> print(new_entity.long_name)
        'Long Name'
        >>> entity = repo.get_by_id(session, 1)
        >>> print(entity.long_name)
        'Long Name'
        >>> entities = repo.get_all(session)
        >>> for entity in entities:
        ...     print(entity.long_name)
        'Entity 1'
        'Entity 2'
        'Entity 3'
        >>> repo.update(session, 1, 'New Short Name', 1.1, 2, 2, 'New Long Name')
        >>> updated_entity = repo.get_by_id(session, 1)
        >>> print(updated_entity.short_name)
        'New Short Name'
        >>> repo.delete(session, 1)
        >>> deleted_entity = repo.get_by_id(session, 1)
        >>> print(deleted_entity)
        None
    """

    def __init__(self, session: Session):
        """
        Initialize a new instance of the ProductRepository class.

        Args:
            session (Session): The SQLAlchemy session for database operations.
        """
        self.session = session

    def create(
        self,
        session: Session,
        long_name: str,
        short_name: str,
        version: float,
        release: int,
        owner_id: int,
    ) -> Products:
        """
        Create a new entity and add it to the database.

        Args:
            long_name (str): The long name of the entity.
            short_name (str): The short name of the entity.
            version (float): The version of the entity.
            release (int): The release of the entity.
            owner_id (int): The ID of the organization that owns the entity.

        Returns:
            Products: The created entity.

        Examples:
            >>> repo = Repository(session)
            >>> new_entity = repo.create('Long Name', 'Short Name', 1.0, 1, 1)
            >>> print(new_entity.long_name)
            'Long Name'
        """
        entity = Products(
            long_name=long_name,
            short_name=short_name,
            version=version,
            release=release,
            owner_id=owner_id,
        )
        session.add(entity)
        session.commit()
        return entity

    def get_by_id(session: Session, id: int) -> Products:
        """
        Get an entity by its ID.

        Args:
            id (int): The ID of the entity to get.

        Returns:
            Products: The entity with the given ID, or None if no such entity exists.

        Examples:
            >>> repo = Repository(session)
            >>> entity = repo.get_by_id(1)
            >>> print(entity.long_name)
            'Long Name'
        """
        return session.query(Products).filter(Products.product_id == id).first()

    def get_all(session: Session) -> list[Products]:
        """
        Get all entities.

        Returns:
            list[Products]: A list of all entities.

        Examples:
            >>> repo = Repository(session)
            >>> entities = repo.get_all()
            >>> for entity in entities:
            ...     print(entity.long_name)
            'Entity 1'
            'Entity 2'
            'Entity 3'
        """
        return session.query(Products).all()

    def update(
        session: Session,
        id: int,
        short_name: str,
        version: float,
        release: int,
        owner_id: int,
        long_name: str = None,
    ) -> None:
        """
        Update an entity.

        Args:
            id (int): The ID of the entity to update.
            short_name (str): The new short name of the entity.
            version (float): The new version of the entity.
            release (int): The new release of the entity.
            owner_id (int): The new owner ID of the entity.
            long_name (str, optional): The new long name of the entity. Defaults to None.

        Examples:
            >>> repo = Repository(session)
            >>> repo.update(1, 'New Short Name', 1.1, 2, 2, 'New Long Name')
            >>> updated_entity = repo.get_by_id(1)
            >>> print(updated_entity.short_name)
            'New Short Name'
        """

    entity = get_by_id(session, id)
    if entity is not None:
        attributes = {
            "long_name": long_name,
            "short_name": short_name,
            "version": version,
            "release": release,
            "owner_id": owner_id,
        }
        for attr, value in attributes.items():
            if value is not None:
                setattr(entity, attr, value)
        session.commit()

    def delete(session: Session, id: int) -> None:
        """
        Delete an entity.

        Args:
            id (int): The ID of the entity to delete.

        Examples:
            >>> repo = Repository(session)
            >>> repo.delete(1)
            >>> deleted_entity = repo.get_by_id(1)
            >>> print(deleted_entity)
            None
        """
        entity = get_by_id(session, id)
        if entity is not None:
            session.delete(entity)
            session.commit()


class ArtifactTypesRepository:
    """
    A repository providing an interface for accessing and manipulating ArtifactTypes entities in the database.

    Attributes:
        session (Session): The SQLAlchemy session for database operations.

    Methods:
        __init__(self, session: Session): Initialize a new instance of the ArtifactTypesRepository class.
        get_by_id(artifact_type_id: int): Retrieve an ArtifactTypes entity by its ID.
        add(type_name: str, description: str): Add a new ArtifactTypes entity to the database.
        update(artifact_type_id: int, type_name: str, description: str): Update an existing ArtifactTypes entity in the database.
        remove(artifact_type_id: int): Remove an existing ArtifactTypes entity from the database.
        get_all(): Retrieve all ArtifactTypes entities from the database.
    """

    def __init__(self, session):
        """
        Initialize the ArtifactTypesRepository with a SQLAlchemy session.

        Args:
            session (Session): The SQLAlchemy session for database operations.

        Example:
            >>> from sqlalchemy import create_engine, sessionmaker
            >>> from sqlalchemy.orm import Session
            >>> engine = create_engine('sqlite:///:memory:')
            >>> Session = sessionmaker(bind=engine)
            >>> session = Session()
            >>> repo = ArtifactTypesRepository(session)
        """
        self.session = session

    def get_by_id(self, artifact_type_id):
        """
        Retrieve an ArtifactTypes entity by its ID.

        Args:
            artifact_type_id (int): The ID of the ArtifactTypes entity.

        Returns:
            ArtifactTypes: The ArtifactTypes entity with the given ID.

        Example:
            >>> artifact_type = repo.get_by_id(1)
            >>> print(artifact_type.type_name)
            'Type1'
        """
        return self.session.query(ArtifactTypes).get(artifact_type_id)

    def add(self, type_name, description):
        """
        Add a new ArtifactTypes entity to the database.

        Args:
            type_name (str): The name of the new ArtifactTypes entity.
            description (str): The description of the new ArtifactTypes entity.

        Returns:
            ArtifactTypes: The newly created ArtifactTypes entity.

        Example:
            >>> new_type = repo.add('Type2', 'Description for Type2')
            >>> print(new_type.type_name)
            'Type2'
        """
        new_type = ArtifactTypes(type_name=type_name, description=description)
        self.session.add(new_type)
        self.session.commit()
        return new_type

    def update(self, artifact_type_id, type_name, description):
        """
        Update an existing ArtifactTypes entity in the database.

        Args:
            artifact_type_id (int): The ID of the ArtifactTypes entity to update.
            type_name (str): The new name of the ArtifactTypes entity.
            description (str): The new description of the ArtifactTypes entity.

        Returns:
            ArtifactTypes: The updated ArtifactTypes entity, or None if no entity with the given ID was found.

        Example:
            >>> updated_type = repo.update(1, 'UpdatedType', 'Updated description')
            >>> print(updated_type.type_name)
            'UpdatedType'
        """
        artifact_type = self.get_by_id(artifact_type_id)
        if artifact_type is not None:
            artifact_type.type_name = type_name
            artifact_type.description = description
            self.session.commit()
        return artifact_type

    def remove(self, artifact_type_id):
        """
        Remove an existing ArtifactTypes entity from the database.

        Args:
            artifact_type_id (int): The ID of the ArtifactTypes entity to remove.

        Returns:
            bool: True if the entity was removed, False otherwise.

        Example:
            >>> result = repo.remove(1)
            >>> print(result)
            True
        """
        artifact_type = self.get_by_id(artifact_type_id)
        if artifact_type is not None:
            self.session.delete(artifact_type)
            self.session.commit()
            return True
        return False

    def get_all(self):
        """
        Retrieve all ArtifactTypes entities from the database.

        Returns:
            list[ArtifactTypes]: A list of all ArtifactTypes entities.

        Example:
            >>> all_types = repo.get_all()
            >>> for artifact_type in all_types:
            ...     print(artifact_type.type_name)
            'Type1'
            'Type2'
        """
        return self.session.query(ArtifactTypes).all()


class BenchmarkArtifactsRepository:
    """
    A repository providing an interface for accessing and manipulating BenchmarkArtifacts entities in the database.

    Attributes:
        session (Session): The SQLAlchemy session for database operations.

    Methods:
        __init__(self, session: Session): Initialize a new instance of the BenchmarkArtifactsRepository class.
        get_by_ids(benchmark_id: int, artifact_id: int): Retrieve a BenchmarkArtifacts entity by its benchmark_id and artifact_id.
        add(benchmark_id: int, artifact_id: int, is_default: bool = False): Add a new BenchmarkArtifacts entity to the database.
        update(benchmark_id: int, artifact_id: int, is_default: bool): Update an existing BenchmarkArtifacts entity in the database.
        remove(benchmark_id: int, artifact_id: int): Remove an existing BenchmarkArtifacts entity from the database.
        get_all_artifacts(self): Retrieves all BenchmarkArtifacts entities.
        get_all_for_benchmark: Retrieves all BenchmarkArtifacts entities for a specific benchmark.
        get_default(benchmark_id: int): Retrieve the default BenchmarkArtifacts entity for a given benchmark_id from the database.
        update_default(benchmark_id: int, new_default_artifact_id: int): Update the default BenchmarkArtifacts entity for a given benchmark_id in the database.
        toggle_default(benchmark_id: int, artifact_id: int): Toggle the is_default status of a BenchmarkArtifacts entity in the database.
        get_default_artifact_of_benchmark(self, benchmark_id: int): Retrieve the default BenchmarkArtifact entity of a specific benchmark.

    Examples:
        # First, create a new SQLAlchemy session
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker

        engine = create_engine('sqlite:///benchmarks.db')
        Session = sessionmaker(bind=engine)
        session = Session()

        # Then, create a new instance of BenchmarkArtifactsRepository using the session
        repo = BenchmarkArtifactsRepository(session)

        # Add a new benchmark artifact
        new_artifact = repo.add(1, 1)
        print(new_artifact.is_default)  # Outputs: False

        # Get a benchmark artifact by its IDs
        artifact = repo.get_by_ids(1, 1)
        print(artifact.is_default)  # Outputs: False

        # Toggle the is_default status of a benchmark artifact
        toggled_artifact = repo.toggle_default(1, 1)
        print(toggled_artifact.is_default)  # Outputs: True

        # Update a benchmark artifact
        updated_artifact = repo.update(1, 1, False)
        print(updated_artifact.is_default)  # Outputs: False

        # Remove a benchmark artifact
        result = repo.remove(1, 1)
        print(result)  # Outputs: True

        # Get all artifacts for a specific benchmark
        artifacts = repo.get_all_for_benchmark(1)
        for artifact in artifacts:
            print(artifact.artifact_id)  # Outputs: 1, 2, 3, etc.

        # Get the default benchmark artifact
        default_artifact = repo.get_default(1)
        print(default_artifact.artifact_id)  # Outputs: 1

        # Update the default benchmark artifact
        result = repo.update_default(1, 2)
        print(result)  # Outputs: True

        # Retrieve the default artifact of a specific benchmark
        default_artifact = repo.get_default_artifact_of_benchmark(1)
        if default_artifact:
            print(default_artifact.name)  # Outputs the name of the default artifact
    """

    def __init__(self, session):
        """
        Initialize the BenchmarkArtifactsRepository with a SQLAlchemy session.

        Args:
            session (Session): The SQLAlchemy session for database operations.

        Example:
            >>> from sqlalchemy import create_engine
            >>> from sqlalchemy.orm import sessionmaker
            >>> engine = create_engine('sqlite:///benchmarks.db')
            >>> Session = sessionmaker(bind=engine)
            >>> session = Session()
            >>> repo = BenchmarkArtifactsRepository(session)
        """
        self.session = session

    def update(self, benchmark_id, artifact_id, is_default):
        """
        Update an existing entity in the database.

        Args:
            benchmark_id (int): The benchmark_id of the entity to update.
            artifact_id (int): The artifact_id of the entity to update.
            is_default (bool): The new is_default status of the entity.

        Returns:
            BenchmarkArtifacts: The updated entity, or None if no entity with the given benchmark_id and artifact_id was found.

        Example:
            >>> updated = repo.update(1, 1, False)
            >>> print(updated.is_default)
            False
        """

        artifact = self.get_by_ids(benchmark_id, artifact_id)
        if artifact is not None:
            artifact.is_default = is_default
            self.session.commit()
        return artifact

    def get_by_ids(self, benchmark_id, artifact_id):
        """
        Retrieve a BenchmarkArtifacts entity by its benchmark_id and artifact_id.

        Args:
            benchmark_id (int): The benchmark_id of the BenchmarkArtifacts entity.
            artifact_id (int): The artifact_id of the BenchmarkArtifacts entity.

        Returns:
            BenchmarkArtifacts: The BenchmarkArtifacts entity with the given benchmark_id and artifact_id.

        Example:
            >>> artifact = repo.get_by_ids(1, 1)
            >>> print(artifact.is_default)
            True
        """
        return self.session.query(BenchmarkArtifacts).get((benchmark_id, artifact_id))

    def add(self, benchmark_id, artifact_id, is_default=False):
        """
        Add a new BenchmarkArtifacts entity to the database.

        This method creates a new BenchmarkArtifacts record with the provided benchmark_id, artifact_id, and is_default status.
        It then adds this record to the database.

        Args:
            benchmark_id (int): The ID of the benchmark to associate with the artifact.
            artifact_id (int): The ID of the artifact to associate with the benchmark.
            is_default (bool, optional): Whether the artifact is the default for the benchmark. Defaults to False.

        Returns:
            BenchmarkArtifacts: The newly created BenchmarkArtifacts entity.

        Raises:
            IntegrityError: If a BenchmarkArtifacts record with the same benchmark_id, artifact_id, and is_default status already exists.

        Example:
            repo = BenchmarkArtifactsRepository(session)

            # Add a new BenchmarkArtifacts record
            new_artifact = repo.add(1, 1, True)

            print(new_artifact.is_default)  # Outputs: True
            print(new_artifact.benchmark_id)  # Outputs: 1
            print(new_artifact.artifact_id)  # Outputs: 1
        """
        try:
            artifact = BenchmarkArtifacts(
                benchmark_id=benchmark_id,
                artifact_id=artifact_id,
                is_default=is_default,
            )
            self.session.add(artifact)
            self.session.commit()
        except IntegrityError:
            self.session.rollback()
            raise ValueError("This operation would violate a database constraint.")

    def remove(self, benchmark_id, artifact_id):
        """
        Remove an existing entity from the database.

        Args:
            benchmark_id (int): The benchmark_id of the entity to remove.
            artifact_id (int): The artifact_id of the entity to remove.

        Returns:
            bool: True if the entity was removed, False otherwise.

        Example:
            >>> result = repo.remove(1, 1)
            >>> print(result)
            True
        """
        artifact = self.get_by_ids(benchmark_id, artifact_id)
        if artifact is not None:
            self.session.delete(artifact)
            self.session.commit()
            return True
        return False

    def get_all_artifacts(self):
        """
        Retrieve all entries from the database.

        Returns:
            list[BenchmarkArtifacts]: A list of all entities.

        Example:
            >>> entities = repo.get_all_artifacts()
            >>> for entity in entities:
            ...     print(entity.benchmark_id, entity.artifact_id)
            1 1
            2 2
            3 3
        """
        return self.session.query(BenchmarkArtifacts).all()

    def toggle_default(self, benchmark_id, artifact_id):
        """
        Toggle the is_default status of an entity in the database.

        Args:
            benchmark_id (int): The benchmark_id of the entity to update.
            artifact_id (int): The artifact_id of the entity to update.

        Returns:
            BenchmarkArtifacts: The updated entity, or None if no entity with the given benchmark_id and artifact_id was found.

        Example:
            >>> entity = repo.get_by_ids(1, 1)
            >>> print(entity.is_default)
            True
            >>> toggled = repo.toggle_default(1, 1)
            >>> print(toggled.is_default)
            False
        """
        artifact = self.get_by_ids(benchmark_id, artifact_id)
        if artifact is not None:
            artifact.is_default = not artifact.is_default
            self.session.commit()
        return artifact

    def get_all_for_benchmark(self, benchmark_id):
        """
        Retrieve all Artifact entities for a given benchmark_id from the database.

        Args:
            benchmark_id (int): The benchmark_id of the entities.

        Returns:
            list[BenchmarkArtifacts]: A list of all entities for the given benchmark_id.

        Example:
            >>> entities = repo.get_all_for_benchmark(1)
            >>> for entity in entities:
            ...     print(entity.artifact_id)
            1
            2
            3
        """
        return self.session.query(BenchmarkArtifacts).filter_by(benchmark_id=benchmark_id).all()

    def get_default(self, benchmark_id):
        """
        Retrieve the default entity for a given benchmark_id from the database.

        Args:
            benchmark_id (int): The benchmark_id of the entity.

        Returns:
            BenchmarkArtifacts: The default entity for the given benchmark_id, or None if no default entity was found.

        Example:
            >>> default = repo.get_default(1)
            >>> print(default.artifact_id)
            1
        """
        return self.session.query(BenchmarkArtifacts).filter_by(benchmark_id=benchmark_id, is_default=True).first()

    def update_default(self, benchmark_id, new_default_id):
        """
        Update the default entity for a given benchmark_id in the database.

        Args:
            benchmark_id (int): The benchmark_id of the entity to update.
            new_default_id (int): The artifact_id of the new default entity.

        Returns:
            bool: True if the default entity was updated, False otherwise.

        Example:
            >>> result = repo.update_default(1, 2)
            >>> print(result)
            True
        """
        current_default = self.get_default(benchmark_id)
        if current_default is not None:
            self.toggle_default(benchmark_id, current_default.artifact_id)

        new_default = self.get_by_ids(benchmark_id, new_default_id)
        if new_default is not None:
            self.toggle_default(benchmark_id, new_default_id)
            return True

        return False

    def get_default_artifact_of_benchmark(self, benchmark_id: int):
        """
        Retrieve the default BenchmarkArtifact entity of a specific benchmark.

        Args:
            benchmark_id (int): The ID of the benchmark.

        Returns:
            BenchmarkArtifact: The default BenchmarkArtifact entity of the specified benchmark, or None if no default artifact is found.
        """
        default_artifact = (
            self.session.query(Artifact)
            .filter(Artifact.is_default == True, Artifact.benchmark_id == benchmark_id)
            .first()
        )
        return default_artifact


class BenchmarkTypeRepository:
    """
    A repository providing an interface for accessing and manipulating BenchmarkType entities in the database.

    Attributes:
        session (Session): The SQLAlchemy session for database operations.

    Methods:
        __init__(self, session: Session): Initialize a new instance of the BenchmarkTypeRepository class.
        get_by_id(benchmark_type_id: int): Retrieve a BenchmarkType entity by its benchmark_type_id.
        add(long_name: str, short_name: str, description: str): Add a new BenchmarkType entity to the database.
        update(benchmark_type_id: int, long_name: str, short_name: str, description: str): Update an existing BenchmarkType entity in the database.
        remove(benchmark_type_id: int): Remove an existing BenchmarkType entity from the database.
        get_all(): Retrieve all BenchmarkType entities from the database.

    Examples:
        # First, create a new SQLAlchemy session
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker

        engine = create_engine('sqlite:///benchmarks.db')
        Session = sessionmaker(bind=engine)
        session = Session()

        # Then, create a new instance of BenchmarkTypeRepository using the session
        repo = BenchmarkTypeRepository(session)

        # Add a new benchmark type
        new_type = repo.add('Long Name', 'Short', 'This is a description.')
        print(new_type.long_name)  # Outputs: 'Long Name'

        # Get a benchmark type by its ID
        type = repo.get_by_id(1)
        print(type.short_name)  # Outputs: 'Short'

        # Update a benchmark type
        updated_type = repo.update(1, 'New Long Name', 'New Short', 'This is a new description.')
        print(updated_type.long_name)  # Outputs: 'New Long Name'

        # Remove a benchmark type
        result = repo.remove(1)
        print(result)  # Outputs: True

        # Get all benchmark types
        types = repo.get_all()
        for type in types:
            print(type.benchmark_type_id)  # Outputs: 1, 2, 3, etc.
    """

    def __init__(self, session):
        """
        Initialize the BenchmarkTypeRepository with a database session.

        Args:
            session (Session): The SQLAlchemy session for database operations.

        Example:
            repo = BenchmarkTypeRepository(session)
        """
        self.session = session

    def get_by_id(self, benchmark_type_id):
        """
        Retrieve a BenchmarkType entity by its benchmark_type_id.

        Args:
            benchmark_type_id (int): The ID of the BenchmarkType entity to retrieve.

        Returns:
            BenchmarkType: The BenchmarkType entity with the given benchmark_type_id, or None if no such entity exists.

        Example:
            type = repo.get_by_id(1)
            print(type.short_name)  # Outputs: 'Short'
        """
        return self.session.query(BenchmarkType).get(benchmark_type_id)

    def add(self, long_name, short_name, description):
        """
        Add a new BenchmarkType entity to the database.

        Args:
            long_name (str): The long name for the new BenchmarkType entity.
            short_name (str): The short name for the new BenchmarkType entity.
            description (str): The description for the new BenchmarkType entity.

        Returns:
            BenchmarkType: The newly created BenchmarkType entity.

        Example:
            new_type = repo.add('Long Name', 'Short', 'This is a description.')
            print(new_type.long_name)  # Outputs: 'Long Name'
        """
        try:
            benchmark_type = BenchmarkType(long_name=long_name, short_name=short_name, description=description)
            self.session.add(benchmark_type)
            self.session.commit()
        except IntegrityError:
            self.session.rollback()
            raise ValueError("A BenchmarkType with this long_name or short_name already exists.")

    def update(self, benchmark_type_id, long_name, short_name, description):
        """
        Update an existing BenchmarkType entity in the database.

        Args:
            benchmark_type_id (int): The ID of the BenchmarkType entity to update.
            long_name (str): The new long name for the BenchmarkType entity.
            short_name (str): The new short name for the BenchmarkType entity.
            description (str): The new description for the BenchmarkType entity.

        Returns:
            BenchmarkType: The updated BenchmarkType entity, or None if no entity with the given benchmark_type_id was found.

        Example:
            updated_type = repo.update(1, 'New Long Name', 'New Short', 'This is a new description.')
            print(updated_type.long_name)  # Outputs: 'New Long Name'
        """
        type = self.get_by_id(benchmark_type_id)
        if type is not None:
            try:
                type.long_name = long_name
                type.short_name = short_name
                type.description = description
                self.session.commit()
            except IntegrityError:
                self.session.rollback()
                raise ValueError("A BenchmarkType with this long_name or short_name already exists.")
        return type

    def remove(self, benchmark_type_id):
        """
        Remove an existing BenchmarkType entity from the database.

        Args:
            benchmark_type_id (int): The ID of the BenchmarkType entity to remove.

        Returns:
            bool: True if the BenchmarkType entity was removed successfully, False otherwise.

        Example:
            result = repo.remove(1)
            print(result)  # Outputs: True
        """
        type = self.get_by_id(benchmark_type_id)
        if type is not None:
            self.session.delete(type)
            self.session.commit()
            return True
        return False

    def get_all(self):
        """
        Retrieve all BenchmarkType entities from the database.

        Returns:
            list[BenchmarkType]: A list of all BenchmarkType entities.

        Example:
            types = repo.get_all()
            for type in types:
                print(type.benchmark_type_id)  # Outputs: 1, 2, 3, etc.
        """
        return self.session.query(BenchmarkType).all()
