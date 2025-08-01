control 'SV-220300' do
  title 'The DBMS must check the validity of data inputs.'
  desc "Invalid user input occurs when a user inserts data or characters into an application's data entry fields and the application is unprepared to process that data. This results in unanticipated application behavior, potentially leading to an application or information system compromise. Invalid user input is one of the primary methods employed when attempting to compromise an application.

All applications need to validate the data users attempt to input to the application for processing. Rules for checking the valid syntax and semantics of information system inputs (e.g., character set, length, numerical range, acceptable values) are in place to verify inputs match specified definitions for format and content. Inputs passed to interpreters are prescreened to prevent the content from being unintentionally interpreted as commands.


This calls for inspection of application source code, which will require collaboration with the application developers. It is recognized that in many cases, the database administrator (DBA) is organizationally separate from the application developers and may have limited, if any, access to source code. Nevertheless, protections of this type are so important to the secure operation of databases that they must not be ignored. At a minimum, the DBA must attempt to obtain assurances from the development organization that this issue has been addressed and must document what has been discovered."
  desc 'check', %q(Review DBMS code, settings, field definitions, constraints, and triggers to determine whether or not data being input into the database is validated.

If code exists that allows invalid data to be acted upon or input into the database, this is a finding.

If field definitions do not exist in the database, this is a finding.

If fields do not contain enabled constraints where required, this is a finding.

- - - - -
Oracle provides built-in processes to keep data and its integrity intact by using constraints.

Integrity Constraint States
Can specify that a constraint is enabled (ENABLE) or disabled (DISABLE). If a constraint is enabled, data is checked as it is entered or updated in the database, and data that does not conform to the constraint is prevented from being entered. If a constraint is disabled, then data that does not conform can be allowed to enter the database.

Additionally, can specify that existing data in the table must conform to the constraint (VALIDATE). Conversely, if specified NOVALIDATE, are not ensured that existing data conforms.

An integrity constraint defined on a table can be in one of the following states:
    ENABLE, VALIDATE
    ENABLE, NOVALIDATE
    DISABLE, VALIDATE
    DISABLE, NOVALIDATE

For details about the meaning of these states and an understanding of their consequences, see the Oracle Database SQL Language Reference. Some of these consequences are discussed here.

Disabling Constraints
To enforce the rules defined by integrity constraints, the constraints should always be enabled. However, consider temporarily disabling the integrity constraints of a table for the following performance reasons:

- When loading large amounts of data into a table

- When performing batch operations that make massive changes to a table (for example, changing every employee's number by adding 1000 to the existing number)

- When importing or exporting one table at a time

In all three cases, temporarily disabling integrity constraints can improve the performance of the operation, especially in data warehouse configurations.

It is possible to enter data that violates a constraint while that constraint is disabled. Thus, always enable the constraint after completing any of the operations listed in the preceding bullet list.

Enabling Constraints
While a constraint is enabled, no row violating the constraint can be inserted into the table. However, while the constraint is disabled, such a row can be inserted. This row is known as an exception to the constraint. If the constraint is in the ENABLE, NOVALIDATE state, violations resulting from data entered while the constraint was disabled remain. The rows that violate the constraint must be either updated or deleted in order for the constraint to be put in the validated state.

Can identify exceptions to a specific integrity constraint while attempting to enable the constraint. See "Reporting Constraint Exceptions". All rows violating constraints are noted in an EXCEPTIONS table, which can be examined.

ENABLE, NOVALIDATE Constraint State
When a constraint is in the ENABLE, NOVALIDATE state, all subsequent statements are checked for conformity to the constraint. However, any existing data in the table is not checked. A table with ENABLE, NOVALIDATE constraints can contain invalid data, but it is not possible to add new invalid data to it. Constraints in the ENABLE, NOVALIDATE state is most useful in data warehouse configurations that are uploading valid OLTP data.

Enabling a constraint does not require validation. Enabling a constraint novalidate is much faster than enabling and validating a constraint. Also, validating a constraint that is already enabled does not require any DML locks during validation (unlike validating a previously disabled constraint). Enforcement guarantees that no violations are introduced during the validation. Hence, enabling without validating reduces the downtime typically associated with enabling a constraint.

Efficient Use of Integrity Constraints: A Procedure

Using integrity constraint states in the following order can ensure the best benefits:
    Disable state.
    Perform the operation (load, export, import).
    ENABLE, NOVALIDATE state.
    Enable state.

Some benefits of using constraints in this order are:
    No locks are held.
    All constraints can go to enable state concurrently.
    Constraint enabling is done in parallel.
    Concurrent activity on table is permitted.

Setting Integrity Constraints Upon Definition
When an integrity constraint is defined in a CREATE TABLE or ALTER TABLE statement, it can be enabled, disabled, or validated or not validated as determined by the specification of the ENABLE/DISABLE clause. If the ENABLE/DISABLE clause is not specified in a constraint definition, the database automatically enables and validates the constraint.

Disabling Constraints Upon Definition
The following CREATE TABLE and ALTER TABLE statements both define and disable integrity constraints:

CREATE TABLE emp (
   empno NUMBER(5) PRIMARY KEY DISABLE,   . . . ;

ALTER TABLE emp
   ADD PRIMARY KEY (empno) DISABLE;

An ALTER TABLE statement that defines and disables an integrity constraint never fails because of rows in the table that violate the integrity constraint. The definition of the constraint is allowed because its rule is not enforced.

Enabling Constraints Upon Definition

The following CREATE TABLE and ALTER TABLE statements both define and enable integrity constraints:

CREATE TABLE emp (
    empno NUMBER(5) CONSTRAINT emp.pk PRIMARY KEY,   . . . ;

ALTER TABLE emp
    ADD CONSTRAINT emp.pk PRIMARY KEY (empno);

An ALTER TABLE statement that defines and attempts to enable an integrity constraint can fail because rows of the table violate the integrity constraint. If this case, the statement is rolled back, and the constraint definition is not stored and not enabled.

When enabling a UNIQUE or PRIMARY KEY constraint, an associated index is created.)
  desc 'fix', 'Modify database code to properly validate data before it is put into the database or acted upon by the database.

Modify database to contain field definitions for each field in the database.

Modify database to contain constraints on database columns and tables that require them for data validity.

Review the application schemas implemented on the system.  Check the DDL for the tables that are created for the applications to see if constraints have been enabled.

- - - - -
Enabling Constraints Upon Definition
The following CREATE TABLE and ALTER TABLE statements both define and enable integrity constraints:
CREATE TABLE emp (
    empno NUMBER(5) CONSTRAINT emp.pk PRIMARY KEY,   . . . ) ;
ALTER TABLE emp
    ADD CONSTRAINT emp.pk PRIMARY KEY (empno);

An ALTER TABLE statement that defines and attempts to enable an integrity constraint can fail because existing rows of the table violate the integrity constraint. In this case, the statement is rolled back, and the constraint definition is not stored and not enabled.

When enabling a UNIQUE or PRIMARY KEY constraint, an associated index is created.'
  impact 0.5
  ref 'DPMS Target Oracle Database 12c'
  tag check_id: 'C-22015r392031_chk'
  tag severity: 'medium'
  tag gid: 'V-220300'
  tag rid: 'SV-220300r879652_rule'
  tag stig_id: 'O121-C2-019500'
  tag gtitle: 'SRG-APP-000251-DB-000160'
  tag fix_id: 'F-22007r392032_fix'
  tag 'documentable'
  tag legacy: ['SV-76275', 'V-61785']
  tag cci: ['CCI-001310']
  tag nist: ['SI-10']
end
