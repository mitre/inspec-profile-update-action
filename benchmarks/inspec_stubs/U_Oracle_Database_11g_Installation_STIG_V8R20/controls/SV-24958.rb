control 'SV-24958' do
  title 'The SQLNet SQLNET.ALLOWED_LOGON_VERSION parameter must be set to a value of 11 or higher.'
  desc 'Unsupported Oracle network client installations may introduce vulnerabilities to the database. Restriction to use of supported versions helps to protect the database and helps to enforce newer, more robust security controls.'
  desc 'check', 'View the SQLNET.ORA file in the ORACLE_HOME/network/admin directory or the directory specified in the TNS_ADMIN environment variable.

Locate the following entry:

SQLNET.ALLOWED_LOGON_VERSION = 11

If the parameter does not exist, this is a Finding.

If the parameter is not set to a value of 11 or higher, this is a Finding.'
  desc 'fix', 'Edit the SQLNET.ORA file to add or edit the entry:

SQLNET.ALLOWED_LOGON_VERSION = 11

Set the value to 11 or higher.'
  impact 0.5
  ref 'DPMS Target Oracle Homes 11g'
  tag check_id: 'C-29494r2_chk'
  tag severity: 'medium'
  tag gid: 'V-16057'
  tag rid: 'SV-24958r2_rule'
  tag stig_id: 'DO6751-ORACLE11'
  tag gtitle: 'SQLNET.ALLOWED_LOGON_VERSION'
  tag fix_id: 'F-26562r2_fix'
  tag 'documentable'
  tag responsibility: 'Database Administrator'
end
