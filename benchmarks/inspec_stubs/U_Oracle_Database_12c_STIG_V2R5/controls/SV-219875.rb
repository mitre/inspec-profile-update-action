control 'SV-219875' do
  title 'Network client connections must be restricted to supported versions.'
  desc 'Unsupported Oracle network client installations may introduce vulnerabilities to the database. Restriction to use of supported versions helps to protect the database and helps to enforce newer, more robust security controls.'
  desc 'check', 'Note: The SQLNET.ALLOWED_LOGON_VERSION parameter is deprecated in Oracle Database 12c. This parameter has been replaced with two new Oracle Net Services parameters:

SQLNET.ALLOWED_LOGON_VERSION_SERVER
SQLNET.ALLOWED_LOGON_VERSION_CLIENT

View the SQLNET.ORA file in the ORACLE_HOME/network/admin directory or the directory specified in the TNS_ADMIN environment variable. (Please see the supplemental file "Non-default sqlnet.ora configurations.pdf" for how to find multiple and/or differently located sqlnet.ora files.)

Locate the following entries:

SQLNET.ALLOWED_LOGON_VERSION_SERVER = 12
SQLNET.ALLOWED_LOGON_VERSION_CLIENT = 12

If the parameters do not exist, this is a finding.

If the parameters are not set to a value of 12 or 12a, this is a finding.

Note: Attempting to connect with a client version lower than specified in these parameters may result in a misleading error:
ORA-01017: invalid username/password: logon denied'
  desc 'fix', 'Edit the SQLNET.ORA file to add or edit the entries:

SQLNET.ALLOWED_LOGON_VERSION_SERVER = 12
SQLNET.ALLOWED_LOGON_VERSION_CLIENT = 12

Set the value to 12 or higher.
Valid values for SQLNET.ALLOWED_LOGON_VERSION_SERVER are: 12 and 12a

Valid values for SQLNET.ALLOWED_LOGON_VERSION_CLIENT are: 12 and 12a

For more information on sqlnet.ora parameters refer to the following document:
"Database Net Services Reference"
http://docs.oracle.com/database/121/NETRF/sqlnet.htm#NETRF006

For more information on configuring authentication refer to the following document:
"Oracle Database 12C Password Version Configuration Guidelines"
https://docs.oracle.com/database/121/DBSEG/authentication.htm#GUID-E6EE45DD-1E3B-4028-B8DE-65D6AA373821'
  impact 0.5
  ref 'DPMS Target Oracle Database 12c'
  tag check_id: 'C-21586r533134_chk'
  tag severity: 'medium'
  tag gid: 'V-219875'
  tag rid: 'SV-219875r401224_rule'
  tag stig_id: 'O121-BP-026600'
  tag gtitle: 'SRG-APP-000516-DB-000363'
  tag fix_id: 'F-21585r533135_fix'
  tag 'documentable'
  tag legacy: ['SV-76025', 'V-61535']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
