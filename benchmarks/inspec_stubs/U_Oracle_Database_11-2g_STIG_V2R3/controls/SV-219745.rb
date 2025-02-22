control 'SV-219745' do
  title 'Remote administration must be disabled for the Oracle connection manager.'
  desc 'Remote administration provides a potential opportunity for malicious users to make unauthorized changes to the Connection Manager configuration or interrupt its service.'
  desc 'check', 'View the cman.ora file in the ORACLE_HOME/network/admin directory.

If the file does not exist, the database is not accessed via Oracle Connection Manager and this check is Not a Finding.

If the entry and value for REMOTE_ADMIN is not listed or is not set to a value of NO (REMOTE_ADMIN = NO), this is a Finding.'
  desc 'fix', 'View the cman.ora file in the ORACLE_HOME/network/admin directory of the Connection Manager.

Include the following line in the file:

REMOTE_ADMIN = NO'
  impact 0.5
  ref 'DPMS Target Oracle Database 11.2g'
  tag check_id: 'C-21470r307084_chk'
  tag severity: 'medium'
  tag gid: 'V-219745'
  tag rid: 'SV-219745r401224_rule'
  tag stig_id: 'O112-BP-026500'
  tag gtitle: 'SRG-APP-000516-DB-000363'
  tag fix_id: 'F-21469r307085_fix'
  tag 'documentable'
  tag legacy: ['SV-68315', 'V-54075']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
