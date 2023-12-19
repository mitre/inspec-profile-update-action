control 'SV-219874' do
  title 'Remote administration must be disabled for the Oracle connection manager.'
  desc 'Remote administration provides a potential opportunity for malicious users to make unauthorized changes to the Connection Manager configuration or interrupt its service.'
  desc 'check', 'View the cman.ora file in the ORACLE_HOME/network/admin directory.

If the file does not exist, the database is not accessed via Oracle Connection Manager and this check is not a finding.

If the entry and value for REMOTE_ADMIN is not listed or is not set to a value of NO (REMOTE_ADMIN = NO), this is a finding.'
  desc 'fix', 'View the cman.ora file in the ORACLE_HOME/network/admin directory of the Connection Manager.

Include the following line in the file:

  REMOTE_ADMIN = NO'
  impact 0.5
  ref 'DPMS Target Oracle Database 12c'
  tag check_id: 'C-21585r533132_chk'
  tag severity: 'medium'
  tag gid: 'V-219874'
  tag rid: 'SV-219874r879887_rule'
  tag stig_id: 'O121-BP-026500'
  tag gtitle: 'SRG-APP-000516-DB-000363'
  tag fix_id: 'F-21584r533133_fix'
  tag 'documentable'
  tag legacy: ['SV-76023', 'V-61533']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
