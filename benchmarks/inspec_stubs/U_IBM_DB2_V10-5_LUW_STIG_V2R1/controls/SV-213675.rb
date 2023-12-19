control 'SV-213675' do
  title 'DB2 must allow only the ISSM (or individuals or roles appointed by the ISSM) to select which auditable events are to be audited.'
  desc "Without the capability to restrict which roles and individuals can select which events are audited, unauthorized personnel may be able to prevent or interfere with the auditing of critical events.

Suppression of auditing could permit an adversary to evade detection.

Misconfigured audits can degrade the system's performance by overwhelming the audit log. Misconfigured audits may also make it more difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one."
  desc 'check', "Run the following command to find the value of the SYSADM_GROUP parameter: 

     $db2 get dbm cfg 

Only users approved by the ISSM should be part of the SYSADM_GROUP. If non-ISSM authorized users are part of SYSADM_GROUP group, this is a finding.

On Windows systems, if the SYSADM_GROUP database manager configuration parameter is not specified, this is a finding.

Database level audit

The security administrator (who holds SECADM authority within a database) can define audit policies and control the audit requirements for an individual database. The security administrator can use the following audit routines to operate upon the database audit logs:

- The SYSPROC.AUDIT_ARCHIVE stored procedure archives audit logs.
- The SYSPROC.AUDIT_LIST_LOGS table function allows you to locate logs of interest.
- The SYSPROC.AUDIT_DELIM_EXTRACT stored procedure extracts data into delimited files for analysis.

The security administrator can also grant EXECUTE privilege on these routines to another user.

Run the following query to find out which users have SECADM authority in database: 
DB2> SELECT CHAR(GRANTOR,35) AS GRANTOR, CHAR(GRANTEE,35) AS GRANTEE, GRANTEETYPE 
           FROM SYSCAT.DBAUTH
           WHERE SECURITYADMAUTH='Y'

If GRANTEETYPE is 'U' and the authorization ID is not an ISSM authorized user, this is a finding. 

If the GRANTEETYPE is 'G', then all members of the external group identified by GRANTEE must be ISSM authorized users, otherwise this is a finding.

If the GRANTEETYPE is 'R', then all members of the database role identified by GRANTEE must be ISSM authorized users, otherwise this is a finding.

The members of a role can be found using this statement: 
DB2> SELECT CHAR(GRANTOR,35) AS GRANTOR, CHAR(GRANTEE,35) AS GRANTEE, GRANTEETYPE
           FROM SYSCAT.ROLEAUTH
           WHERE ROLENAME= <search role name>

Run the following query to find out which users have execute privilege on SYSPROC.AUDIT_ARCHIVE, SYSPROC.AUDIT_LIST_LOGS, SYSPROC.AUDIT_DELIM_EXTRACT: 
DB2> SELECT * 
           FROM SYSCAT.ROUTINEAUTH
           WHERE SPECIFICNAME LIKE 'AUDIT%' AND SCHEMA='SYSPROC'

If non-ISSM authorized users have execute privilege on any of above three routines, this is a finding."
  desc 'fix', 'Update the value SYSADM_GROUP to a group which has only members approved by the ISSM using the following command: 

     $db2 update dbm cfg using SYSADM_GROUP <SYSADMIN GROUP>

Remove users not approved by ISSM from SYSADM_GROUP group using operating system tools/commands.

Revoke SECADM authority from non-ISSM users using the SQL statement: 
DB2> REVOKE SECADM ON DATABASE FROM USER <user name> 

Remove non-ISSM members using the following the following SQL statement: 
DB2> REVOKE SECADM ON DATABASE FROM GROUP <group name> 

Revoke SECADM from the group or role using the following SQL statement: 
DB2> REVOKE SECADM ON DATABASE FROM ROLE <role name> 

Revoke execute from unapproved users if they have execute on SYSPROC.AUDIT_ARCHIVE, SYSPROC.AUDIT_LIST_LOGS, SYSPROC.AUDIT_DELIM_EXTRACT using appropriate variation of Revoke (routine privileges) statement.

Note: The audit facility provides the ability to audit at both the instance and the individual database level, independently recording all instance and database level activities with separate logs for each instance level audit.

The system administrator (who holds SYSADM authority) can use the db2audit tool to configure audit at the instance level as well as to control when such audit information is collected. The system administrator can use the db2audit tool to archive both instance and database audit logs as well as to extract audit data from archived logs of either type.

SYSADM authority is assigned to the group specified by the SYSADM_GROUP configuration parameter. Membership in that group is controlled outside the database manager through the security facility used on your platform.'
  impact 0.5
  ref 'DPMS Target IBM DB2 V10.5 LUW'
  tag check_id: 'C-14896r295074_chk'
  tag severity: 'medium'
  tag gid: 'V-213675'
  tag rid: 'SV-213675r879560_rule'
  tag stig_id: 'DB2X-00-000700'
  tag gtitle: 'SRG-APP-000090-DB-000065'
  tag fix_id: 'F-14894r295075_fix'
  tag 'documentable'
  tag legacy: ['SV-89113', 'V-74439']
  tag cci: ['CCI-000171']
  tag nist: ['AU-12 b']
end
