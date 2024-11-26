control 'SV-24955' do
  title 'Remote administration should be disabled for the Oracle connection manager.'
  desc 'Remote administration provides a potential opportunity for malicious users to make unauthorized changes to the Connection Manager configuration or interrupt its service.'
  desc 'check', 'View the cman.ora file in the ORACLE_HOME/network/admin directory.

If the file does not exist, the database is not accessed via Oracle Connection Manager and this check is Not a Finding.

If the entry and value for REMOTE_ADMIN is not listed or is not set to a value of NO (REMOTE_ADMIN = NO), this is a Finding.'
  desc 'fix', 'View the cman.ora file in the ORACLE_HOME/network/admin directory of the Connection Manager.

Include the following line in the file:

  REMOTE_ADMIN = NO'
  impact 0.5
  ref 'DPMS Target Oracle Homes 11g'
  tag check_id: 'C-29493r1_chk'
  tag severity: 'medium'
  tag gid: 'V-16032'
  tag rid: 'SV-24955r1_rule'
  tag stig_id: 'DO6747-ORACLE11'
  tag gtitle: 'Connection Manager remote administration'
  tag fix_id: 'F-26561r1_fix'
  tag 'documentable'
  tag responsibility: 'Database Administrator'
end
