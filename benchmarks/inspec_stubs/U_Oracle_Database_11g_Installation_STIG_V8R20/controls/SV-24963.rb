control 'SV-24963' do
  title 'Oracle Configuration Manager should not remain installed on a production system.'
  desc 'Oracle Configuration Manager (OCM) is a function of the Oracle Software Configuration Manager (SCM). OCM collects system configuration data used for automated upload to systems owned and managed by Oracle to assist in providing customer support. The configuration information about the server that the OCM collects includes IP addresses, hostname, database username, location of datafiles, etc.'
  desc 'check', "NOTE: The collection does not include application or custom data within the database. If released to unauthorized persons, system configuration data may be used by malicious persons to gain additional unauthorized access to the database or other systems.

On UNIX Systems:

  ls $ORACLE_HOME/ccr

On Windows Systems (From Windows Explorer):

  Browse to the %ORACLE_HOME% directory.

If the directory ORACLE_HOME\\ccr does not exist, this is not a Finding.

If the ccr directory exists, confirm if any of the Oracle databases have been configured for OCM:

From SQL*Plus:

  select username from dba_users where username = 'ORACLE_OCM';

If the account exists, OCM has been installed (on this database) and is a Finding."
  desc 'fix', 'Remove Oracle Configuration Manager.

Details for removal are provided in Oracle MetaLink Note 369111.1 or in MetaLink Note 728989.1 for a link to the OCM Installation and Administration Guide.'
  impact 0.5
  ref 'DPMS Target Oracle Homes 11g'
  tag check_id: 'C-29496r1_chk'
  tag severity: 'medium'
  tag gid: 'V-16056'
  tag rid: 'SV-24963r1_rule'
  tag stig_id: 'DO6754-ORACLE11'
  tag gtitle: 'Oracle Configuration Manager'
  tag fix_id: 'F-26564r1_fix'
  tag 'documentable'
  tag responsibility: 'Database Administrator'
end
