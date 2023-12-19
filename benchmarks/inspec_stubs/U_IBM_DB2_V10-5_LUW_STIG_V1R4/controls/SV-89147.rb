control 'SV-89147' do
  title 'Database objects (including but not limited to tables, indexes, storage, stored procedures, functions, triggers, links to software external to DB2, etc.) must be owned by database/DBMS principals authorized for ownership.'
  desc "Within the database, object ownership implies full privileges to the owned object, including the privilege to assign access to the owned objects to other subjects. Database functions and procedures can be coded using definer's rights. This allows anyone who utilizes the object to perform the actions if they were the owner. If not properly managed, this can lead to privileged actions being taken by unauthorized individuals.

Conversely, if critical tables or other objects rely on unauthorized owner accounts, these objects may be lost when an account is removed."
  desc 'check', 'Get the list of authorized owners from ISSO or DBA.

Use the following catalog views/queries to find the ownership of the various database objects:

Select libname,owner from syscat.libraries
Select modulename,owner from syscat.modules
Select tabname,owner from syscat.nicknames
Select pkgname,owner from syscat.packages
Select routinename,owner from syscat.routines
Select seqname,owner from syscat.sequences
Select constname,owner from syscat.tabconst
Select tabname,owner from syscat.tables
Select tbspace,owner from syscat.tablespaces
Select trigname,owner from syscat.triggers

If any owner is not in the ISSO/DBA provided list, this is a finding.'
  desc 'fix', 'Use the list identified in check. Drop and create the objects as necessary with the correct ownership.
DB2> DROP
DB2> CREATE

Note: For additional information regarding the DROP statement, select the following link:
http://www-01.ibm.com/support/knowledgecenter/SSEPGG_10.5.0/com.ibm.db2.luw.sql.ref.doc/doc/r0000945.html?lang=en'
  impact 0.5
  ref 'DPMS Target IBM DB2 LUW 10.5 for Linux'
  tag check_id: 'C-74399r3_chk'
  tag severity: 'medium'
  tag gid: 'V-74473'
  tag rid: 'SV-89147r1_rule'
  tag stig_id: 'DB2X-00-003200'
  tag gtitle: 'SRG-APP-000133-DB-000200'
  tag fix_id: 'F-81073r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
