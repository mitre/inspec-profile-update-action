control 'SV-213687' do
  title 'DB2 must protect its audit features from unauthorized removal.'
  desc 'Protecting audit data also includes identifying and protecting the tools used to view and manipulate log data. Therefore, protecting audit tools is necessary to prevent unauthorized operation on audit data.

Applications providing tools to interface with audit data will leverage user permissions and roles identifying the user accessing the tools and the corresponding rights the user enjoys in order make access decisions regarding the deletion of audit tools.

Audit tools include, but are not limited to, vendor-provided and open source audit tools needed to successfully view and manipulate audit information system activity and records. Audit tools include custom queries and report generators.'
  desc 'check', "Run the following command to find the value of the SYSADM_GROUP parameter:

     $db2 get dbm cfg 

Only authorized OS users should be part of this group. If non-authorized users are part of the SYSADM_GROUP group, this is a finding.

On Windows systems, if the SYSADM_GROUP database manager configuration parameter is not specified, this is a finding.

The security administrator (who holds SECADM authority within a database) can define audit policies and control the audit requirements for an individual database. The security administrator can use the following audit routines to operate upon the database audit logs:

- The SYSPROC.AUDIT_ARCHIVE stored procedure archives audit logs.
- The SYSPROC.AUDIT_LIST_LOGS table function allows you to locate logs of interest.
- The SYSPROC.AUDIT_DELIM_EXTRACT stored procedure extracts data into delimited files for analysis.

The security administrator can also grant EXECUTE privilege on these routines to another user.

Run the following query to find out which users have SECADM authority in database: 

DB2> SELECT CHAR(GRANTOR,35) AS GRANTOR, CHAR(GRANTEE,35) AS GRANTEE, GRANTEETYPE  
           FROM SYSCAT.DBAUTH 
           WHERE SECURITYADMAUTH='Y'

If GRANTEETYPE is 'U' and the authorization ID is not an authorized user, this is a finding.

If the GRANTEETYPE is 'G', then all members of the external group identified by GRANTEE must be authorized users, otherwise, this is a finding.

If the GRANTEETYPE is 'R', then all members of the database role identified by GRANTEE must be authorized users, otherwise, this is a finding.

The members of a role can be found using this statement: 

DB2> SELECT CHAR(GRANTOR,35) AS GRANTOR, CHAR(GRANTEE,35) AS GRANTEE, GRANTEETYPE 
           FROM SYSCAT.ROLEAUTH 
           WHERE ROLENAME= <search role name>

Run the following query to find out which users have execute privilege on SYSPROC.AUDIT_ARCHIVE, SYSPROC.AUDIT_LIST_LOGS, SYSPROC.AUDIT_DELIM_EXTRACT:
DB2> SELECT * 
           FROM SYSCAT.ROUTINEAUTH 
           WHERE SPECIFICNAME LIKE 'AUDIT%' AND SCHEMA='SYSPROC'

If non-authorized users have EXECUTE privilege on any of above three routines, this is a finding."
  desc 'fix', 'Update the value of SYSADM_GROUP to a group which has only authorized members.

     $db2 update dbm cfg using SYSADM_GROUP <SYSADMIN GROUP>

Remove unauthorized users from the SYSADM_GROUP using the operating system tools/commands. 

Revoke SECADM authority from non-authorized users using the SQL statement below:
DB2> REVOKE SECADM ON DATABASE FROM USER <user name> 

Remove non-authorized members or revokes SECADM from the group or role using this SQL statement:
DB2> REVOKE SECADM ON DATABASE FROM GROUP <group name> 
DB2> REVOKE SECADM ON DATABASE FROM ROLE <role name> 

Revoke execute from non-authorized users if they have execute on SYSPROC.AUDIT_ARCHIVE, SYSPROC.AUDIT_LIST_LOGS, SYSPROC.AUDIT_DELIM_EXTRACT using the appropriate variation of Revoke (routine privileges) statement.'
  impact 0.5
  ref 'DPMS Target IBM DB2 V10.5 LUW'
  tag check_id: 'C-14908r295110_chk'
  tag severity: 'medium'
  tag gid: 'V-213687'
  tag rid: 'SV-213687r879581_rule'
  tag stig_id: 'DB2X-00-002700'
  tag gtitle: 'SRG-APP-000123-DB-000204'
  tag fix_id: 'F-14906r295111_fix'
  tag 'documentable'
  tag legacy: ['SV-89137', 'V-74463']
  tag cci: ['CCI-001495']
  tag nist: ['AU-9']
end
