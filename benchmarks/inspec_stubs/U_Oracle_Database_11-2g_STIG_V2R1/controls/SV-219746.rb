control 'SV-219746' do
  title 'The SQLNet SQLNET.ALLOWED_LOGON_VERSION parameter must be set to a value of 12 or higher.'
  desc 'Unsupported Oracle network client installations may introduce vulnerabilities to the database. Restriction to use of supported versions helps to protect the database and helps to enforce newer, more robust security controls.'
  desc 'check', 'View the SQLNET.ORA file in the ORACLE_HOME/network/admin directory or the directory specified in the TNS_ADMIN environment variable. (Please see the supplemental file "Non-default sqlnet.ora configurations.pdf" for how to find multiple and/or differently located sqlnet.ora files.)

Locate the following entry:

SQLNET.ALLOWED_LOGON_VERSION = 12

If the parameter does not exist, this is a finding.
Determine whether the Oracle DBMS software is at version 11.2.0.4 with the January 2014 CPU (or above). If it is not, this is a finding.

If the parameter is not set to a value of 12 or higher, this is a finding.'
  desc 'fix', ': Deploy Oracle 11.2.0.4 with the January 2014 CPU patch.

Edit the SQLNET.ORA file to add or edit the entry:

SQLNET.ALLOWED_LOGON_VERSION = 12

Set the value to 12 or higher.

For more information on sqlnet.ora parameters refer to the following document:
"Database Net Services Reference"
https://docs.oracle.com/cd/E11882_01/network.112/e10835/sqlnet.htm#NETRF006'
  impact 0.5
  ref 'DPMS Target Oracle Database 11.2g'
  tag check_id: 'C-21471r307087_chk'
  tag severity: 'medium'
  tag gid: 'V-219746'
  tag rid: 'SV-219746r401224_rule'
  tag stig_id: 'O112-BP-026600'
  tag gtitle: 'SRG-APP-000516-DB-000363'
  tag fix_id: 'F-21470r307088_fix'
  tag 'documentable'
  tag legacy: ['SV-68317', 'V-54077']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
