control 'SV-24705' do
  title 'DBMS application user roles should not be assigned unauthorized privileges.'
  desc 'Unauthorized access to the data can lead to loss of confidentiality and integrity of the data.'
  desc 'check', 'Compare privileges assigned to database application user roles to those defined in the System Security Plan.

If the assigned privileges do not match the authorized list of privileges, this is a Finding.'
  desc 'fix', 'Use the grant and revoke commands to assign the authorized privileges as listed in the System Security Plan to custom database application or application user roles.'
  impact 0.5
  ref 'DPMS Target Oracle Databases 11g'
  tag check_id: 'C-1092r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15128'
  tag rid: 'SV-24705r1_rule'
  tag stig_id: 'DG0105-ORACLE11'
  tag gtitle: 'DBMS application user role privilege assignment'
  tag fix_id: 'F-2558r1_fix'
  tag 'documentable'
  tag responsibility: 'Database Administrator'
end
