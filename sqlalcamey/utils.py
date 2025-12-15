# utils.py
from typing import Type, Optional, Any, Dict, List, Union
from sqlalchemy.orm import Session
from sqlalchemy.sql.schema import Column
from sqlalchemy.ext.declarative import DeclarativeMeta


# The `table:`` parameter is used, but it might not be immediately obvious where.

# In SQLAlchemy, when you perform a query, you specify the model class
# (which represents a table in your database) as an argument to session.query().
# In this function, table is used in this way.

# The line session.query(column).filter(filter_column == id).first() is where table
# is used indirectly. Here, column and filter_column are expected to be attributes
# of an instance of table. When you pass Statuses.name and Statuses.status_id as
# column and filter_column respectively, you're actually passing attributes of
# the Statuses model, which represents a table in your database.

# So, while table isn't explicitly mentioned in the function body, it's used to
# derive the column and filter_column parameters. The function wouldn't work correctly
# if column and filter_column weren't attributes of table.


def get_column_value_by_id(
    session: Session,
    table: Type[DeclarativeMeta],
    column: Column,
    filter_column: Column,
    id: int,
) -> Optional[Any]:
    """
    Retrieves a specific column value for a record in a table, given the record's ID.

    Args:
        session (sqlalchemy.orm.Session): The session object used to execute database queries.
        table (sqlalchemy.ext.declarative.api.DeclarativeMeta): The SQLAlchemy model class representing the table.
        column (sqlalchemy.sql.schema.Column): The column in the table that you want to retrieve.
        filter_column (sqlalchemy.sql.schema.Column): The column in the table that you want to filter on.
        id (int): The ID of the record you want to retrieve.

    Returns:
        Any: The value of the specified column for the record with the given ID. If no such record exists, returns None.

    Example:
        from sqlalchemy.orm import Session
        # the table from models you want to access
        from .models import Statuses
        # create a new session
        session = Session()
        # get the name of the status with ID 1
        name = get_column_value_by_id(session, Statuses, Statuses.name, Statuses.status_id, 1)
        print(name)
    """
    result = session.query(column).filter(filter_column == id).first()
    if result is not None:
        return result[0]
    else:
        return None


def update_column_value_by_id(
    session: Session,
    table: Type[DeclarativeMeta],
    column: Column,
    filter_column: Column,
    id: int,
    new_value: Any,
) -> None:
    """
    Updates a specific column value for a record in a table, given the record's ID.

    Args:
        session (sqlalchemy.orm.Session): The session object used to execute database queries.
        table (sqlalchemy.ext.declarative.api.DeclarativeMeta): The SQLAlchemy model class representing the table.
        column (sqlalchemy.sql.schema.Column): The column in the table that you want to update.
        filter_column (sqlalchemy.sql.schema.Column): The column in the table that you want to filter on.
        id (int): The ID of the record you want to update.
        new_value (Any): The new value that you want to set for the specified column.

    Example:
        from sqlalchemy.orm import Session
        from .models import Statuses
        # create a new session
        session = Session()
        # update the name of the status with ID 1
        update_column_value_by_id(session, Statuses, Statuses.name, Statuses.status_id, 1, 'New Name')
    """
    record = session.query(table).filter(filter_column == id).first()
    if record is not None:
        setattr(record, column.name, new_value)
        session.commit()


def get_values_in_row_by_id(
    session: Session,
    table: Type[DeclarativeMeta],
    columns: Union[Dict[str, Column], List[Column]],
    filter_column: Column,
    id: int,
) -> Optional[Union[Dict[str, Any], List[Any]]]:
    """
    Retrieves specific column values for a record in a table, given the record's ID.

    Args:
        session (sqlalchemy.orm.Session): The session object used to execute database queries.
        table (sqlalchemy.ext.declarative.api.DeclarativeMeta): The SQLAlchemy model class representing the table.
        columns (Union[Dict[str, sqlalchemy.sql.schema.Column], List[sqlalchemy.sql.schema.Column]]): Either a dictionary where the keys are the names of the columns you want to retrieve and the values are the corresponding Column objects, or a list of Column objects.
        filter_column (sqlalchemy.sql.schema.Column): The column in the table that you want to filter on.
        id (int): The ID of the record you want to retrieve.

    Returns:
        Union[Dict[str, Any], List[Any]]:
        If columns is a dictionary, returns a dictionary where the keys are the names of the columns and the values are the values of those columns for the record with the given ID.
        If columns is a list, returns a list of the values of the specified columns for the record with the given ID. If no such record exists, returns None.

    Example:
        from sqlalchemy.orm import Session
        from .models import Statuses
        # create a new session
        session = Session()

        # get some values in the row with ID 1 using a dictionary of columns
        values_dict = get_values_in_row_by_id(session, Statuses, {'name': Statuses.name, 'status': Statuses.status}, Statuses.status_id, 1)
        print(values_dict)

        # get some values in the row with ID 1 using a list of columns
        values_list = get_values_in_row_by_id(session, Statuses, [Statuses.name, Statuses.status], Statuses.status_id, 1)
        print(values_list)
    """
    if isinstance(columns, dict):
        record = session.query(*columns.values()).filter(filter_column == id).first()
        if record is not None:
            return {key: value for key, value in zip(columns.keys(), record)}
    elif isinstance(columns, list):
        record = session.query(*columns).filter(filter_column == id).first()
        if record is not None:
            return list(record)
    else:
        return None


def get_all_values_in_row_by_id(
    session: Session, table: Type[DeclarativeMeta], filter_column: Column, id: int
) -> Optional[DeclarativeMeta]:
    """
    Retrieves all column values for a record in a table, given the record's ID.

    Args:
        session (sqlalchemy.orm.Session): The session object used to execute database queries.
        table (sqlalchemy.ext.declarative.api.DeclarativeMeta): The SQLAlchemy model class representing the table.
        filter_column (sqlalchemy.sql.schema.Column): The column in the table that you want to filter on.
        id (int): The ID of the record you want to retrieve.

    Returns:
        DeclarativeMeta: An instance of the table class representing the record with the given ID. If no such record exists, returns None.

    Example:
        from sqlalchemy.orm import Session
        from .models import Statuses
        # create a new session
        session = Session()
        # get all values in the row with ID 1
        row = get_all_values_in_row_by_id(session, Statuses, Statuses.status_id, 1)
        print(row)
    """
    record = session.query(table).filter(filter_column == id).first()
    return record
