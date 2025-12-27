control 'SV-219762' do
  title 'The DBMS must protect audit information from unauthorized modification.'
  desc 'If audit data were to become compromised, then competent forensic analysis and discovery of the true source of potentially malicious system activity is impossible to achieve. 

To ensure the veracity of audit data, the information system and/or the application must protect audit information from unauthorized modification.  

This requirement can be achieved through multiple methods which will depend upon system architecture and design. Some commonly employed methods include ensuring log files enjoy the proper file system permissions and limiting log data locations.  

Applications providing a user interface to audit data will leverage user permissions and roles identifying the user accessing the data and the corresponding rights that the user enjoys in order to make access decisions regarding the modification of audit data.

Audit information includes all information (e.g., audit records, audit settings, and audit reports) needed to successfully audit information system activity. 

Modification of database audit data could mask the theft of, or the unauthorized modification of, sensitive data stored in the database.'
  desc 'check', "Review locations of audit logs, both internal to the database and database audit logs located at the operating system-level. Verify there are appropriate controls and permissions to protect the audit information from unauthorized modification. If appropriate controls and permissions do not exist, this is a finding.
- - - - - -
DBA_TAB_PRIVS describes all object grants in the database.  Check to see who has permissions on the AUD$ table.  

Related View

DBA_TAB_PRIVS describes the object grants for which the current user is the object owner, grantor, or grantee.
Column      Datatype      NULL      Description
GRANTEE  VARCHAR2(30)  NOT NULL  Name of the user to whom access was granted
OWNER      VARCHAR2(30)  NOT NULL  Owner of the object
TABLE_NAME  VARCHAR2(30)  NOT NULL  Name of the object
GRANTOR  VARCHAR2(30)  NOT NULL  Name of the user who performed the grant
PRIVILEGE  VARCHAR2(40)  NOT NULL  Privilege on the object
GRANTABLE  VARCHAR2(3)             Indicates whether the privilege was granted with the GRANT OPTION (YES) or not (NO)
HIERARCHY  VARCHAR2(3)             Indicates whether the privilege was granted with the HIERARCHY OPTION (YES) or not (NO)

sqlplus connect as sysdba;

SQL>  SELECT GRANTEE, TABLE_NAME, COLUMN_NAME, PRIVILEGE
      FROM DBA_COL_PRIVS where table_name = 'AUD$';"
  desc 'fix', %q(Add controls and modify permissions to protect database audit log data from unauthorized modification, whether stored in the database itself or at the OS level.
- - - - -
Revoke access to the AUD$ table to anyone who you do not want to have access to the AUD$ table.

In the check we looked for all users who had access to the AUD$ table. To fix this, use the REVOKE command to revoke access to users who should not have access to the audit data.

REVOKE statement

Use the REVOKE statement to remove permissions from a specific user or from all users to perform actions on database objects.
The following types of permissions can be revoked:
    Delete data from a specific table.
    Insert data into a specific table.
    Create a foreign key reference to the named table or to a subset of columns from a table.
    Select data from a table, view, or a subset of columns in a table.
    Create a trigger on a table.
    Update data in a table or in a subset of columns in a table.
    Run a specified routine (function or procedure).

If a user named FRED had access to the AUD$ table and you want to revoke that access, use the following command. The syntax that you use for the REVOKE statement for tables is as follows:

REVOKE privilege-type ON [ TABLE ] { table-Name | view-Name } FROM grantees


SQL>REVOKE SELECT ON TABLE AUD$ FROM FRED; 

Revoking a privilege without specifying a column list revokes the privilege for all of the columns in the table.
Syntax for routines

table-privileges include

  DELETE |
  INSERT |
  REFERENCES [column list] |
  SELECT [column list] |
  TRIGGER |
  UPDATE [column list] 

column list

  ( column-identifier {, column-identifier}* ) 

Use the ALL PRIVILEGES privilege type to revoke all of the permissions from the user for the specified table. You can also revoke one or more table privileges by specifying a privilege-list.

Use the DELETE privilege type to revoke permission to delete rows from the specified table.

Use the INSERT privilege type to revoke permission to insert rows into the specified table.

Use the REFERENCES privilege type to revoke permission to create a foreign key reference to the specified table. If a column list is specified with the REFERENCES privilege, the permission is revoked on only the foreign key reference to the specified columns.

Use the SELECT privilege type to revoke permission to perform SELECT statements on a table or view. If a column list is specified with the SELECT privilege, the permission is revoked on only those columns. If no column list is specified, then the privilege is valid on all of the columns in the table.

Use the TRIGGER privilege type to revoke permission to create a trigger on the specified table.

Use the UPDATE privilege type to revoke permission to use the UPDATE statement on the specified table. If a column list is specified, the permission is revoked only on the specified columns.
grantees

  { authorization ID | PUBLIC } [,{ authorization ID | PUBLIC } ] *

You can revoke the privileges from specific users or from all users. Use the keyword PUBLIC to specify all users. The privileges revoked from PUBLIC and from individual users are independent privileges. For example, a SELECT privilege on table t is granted to both PUBLIC and to the authorization ID harry. The SELECT privilege is later revoked from the authorization ID 'Harry', but the authorization ID 'Harry' can access the table through the PUBLIC privilege.

Restriction: You cannot revoke the privileges of the owner of an object.
routine-designator

  {
   qualified-name [ signature ]
  }

Cascading object dependencies

For views, triggers, and constraints, if the privilege on which the object depends on is revoked, the object is automatically dropped. Derby does not try to determine if you have other privileges that can replace the privileges that are being revoked. For more information, see "SQL standard authorization" in the Java DB Developer's Guide.
Limitations

The following limitations apply to the REVOKE statement:

Table-level privileges
    All of the table-level privilege types for a specified grantee and table ID are stored in one row in the SYSTABLEPERMS system table. For example, when user2 is granted the SELECT and DELETE privileges on table user1.t1, a row is added to the SYSTABLEPERMS table. The GRANTEE field contains user2 and the TABLEID contains user1.t1. The SELECTPRIV and DELETEPRIV fields are set to Y. The remaining privilege type fields are set to N.

    When a grantee creates an object that relies on one of the privilege types, the Derby engine tracks the dependency of the object on the specific row in the SYSTABLEPERMS table. For example, user2 creates the view v1 by using the statement SELECT * FROM user1.t1; the dependency manager tracks the dependency of view v1 on the row in SYSTABLEPERMS for GRANTEE(user2), TABLEID(user1.t1). The dependency manager knows only that the view is dependent on a privilege type in that specific row but does not track exactly which privilege type the view is dependent on.

    When a REVOKE statement for a table-level privilege is issued for a grantee and table ID, all of the objects that are dependent on the grantee and table ID are dropped. For example, if user1 revokes the DELETE privilege on table t1 from user2, the row in SYSTABLEPERMS for GRANTEE(user2), TABLEID(user1.t1) is modified by the REVOKE statement. The dependency manager sends a revoke invalidation message to the view user2.v1, and the view is dropped, even though the view is not dependent on the DELETE privilege for GRANTEE(user2), TABLEID(user1.t1).

Column-level privileges
    Only one type of privilege for a specified grantee and table ID are stored in one row in the SYSCOLPERMS system table. For example, when user2 is granted the SELECT privilege on table user1.t1 for columns c12 and c13, a row is added to the SYSCOLPERMS. The GRANTEE field contains user2, the TABLEID contains user1.t1, the TYPE field contains S, and the COLUMNS field contains c12, c13.

    When a grantee creates an object that relies on the privilege type and the subset of columns in a table ID, the Derby engine tracks the dependency of the object on the specific row in the SYSCOLPERMS table. For example, user2 creates the view v1 by using the statement SELECT c11 FROM user1.t1; the dependency manager tracks the dependency of view v1 on the row in SYSCOLPERMS for GRANTEE(user2), TABLEID(user1.t1), TYPE(S). The dependency manager knows that the view is dependent on the SELECT privilege type but does not track exactly which columns the view is dependent on.

    When a REVOKE statement for a column-level privilege is issued for a grantee, table ID, and type, all of the objects that are dependent on the grantee, table ID, and type are dropped. For example, if user1 revokes the SELECT privilege on column c12 on table user1.t1 from user2, the row in SYSCOLPERMS for GRANTEE(user2), TABLEID(user1.t1), TYPE(S) is modified by the REVOKE statement. The dependency manager sends a revoke invalidation message to the view user2.v1, and the view is dropped, even though the view is not dependent on the column c12 for GRANTEE(user2), TABLEID(user1.t1), TYPE(S).

Revoke examples
To revoke the SELECT privilege on table t from the authorization IDs 'Maria' and 'Harry', use the following syntax:

SQL>REVOKE SELECT ON TABLE t FROM maria,harry 

To revoke the UPDATE and TRIGGER privileges on table t from the authorization IDs 'Anita' and 'Zhi', use the following syntax:

SQL>REVOKE UPDATE, TRIGGER ON TABLE t FROM anita,zhi 

To revoke the SELECT privilege on table s.v from all users, use the following syntax:

SQL>REVOKE SELECT ON TABLE s.v FROM PUBLIC

To revoke the UPDATE privilege on columns c1 and c2 of table s.v from all users, use the following syntax:

SQL>REVOKE UPDATE (c1,c2) ON TABLE s.v FROM PUBLIC

To revoke the EXECUTE privilege on procedure p from the authorization ID 'George', use the following syntax:
SQL>REVOKE EXECUTE ON PROCEDURE p FROM george RESTRICT)
  impact 0.5
  ref 'DPMS Target Oracle Database 11.2g'
  tag check_id: 'C-21487r307135_chk'
  tag severity: 'medium'
  tag gid: 'V-219762'
  tag rid: 'SV-219762r395823_rule'
  tag stig_id: 'O112-C2-009400'
  tag gtitle: 'SRG-APP-000119-DB-000060'
  tag fix_id: 'F-21486r307136_fix'
  tag 'documentable'
  tag legacy: ['SV-66401', 'V-52185']
  tag cci: ['CCI-000163']
  tag nist: ['AU-9 a']
end
