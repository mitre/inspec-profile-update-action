# https://www.youtube.com/watch?v=1Va493SMTcY&t=2637s
from sqlalchemy.ext.automap import automap_base
from sqlalchemy.orm import Session
from sqlalchemy import create_engine
from sqlalchemy import inspect

Base = automap_base()

# engine, suppose it has two tables 'user' and 'address' set up
engine = create_engine("sqlite:///database/test.db")

# reflect the tables
Base.prepare(autoload_with=engine)

# mapped classes are now created with names by default
# matching that of the table name.

Benchmarks = Base.classes.Benchmarks
Artifact = Base.classes.Artifact
Organization = Base.classes.Organization
Statuses = Base.classes.Statuses
Products = Base.classes.Products

artifact_types = Base.classes.artifact_types
benchmark_artifacts = Base.classes.benchmark_artifacts
benchmark_type = Base.classes.benchmark_type

session = Session(engine)
inspector = inspect(engine)


import ipdb

ipdb.set_trace()

# rudimentary relationships are produced
session.add(Address(email_address="foo@bar.com", user=User(name="foo")))
session.commit()

# collection-based relationships are by default named
# "<classname>_collection"
u1 = session.query(User).first()
print(u1.address_collection)
