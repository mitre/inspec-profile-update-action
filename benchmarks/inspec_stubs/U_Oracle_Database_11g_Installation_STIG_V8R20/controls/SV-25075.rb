control 'SV-25075' do
  title 'The DBMS should not have a connection defined to access or be accessed by a DBMS at a different classification level.'
  desc 'Applications that access databases and databases connecting to remote databases that differ in their assigned classification levels may expose sensitive data to unauthorized clients. Any interconnections between databases or applications and databases differing in classification levels are required to comply with interface control rules.'
  desc 'check', 'Review database links or other connections defined for the database to access or be accessed by remote databases or other applications as defined in the AIS Functional Architecture documentation or the System Security Plan.

If any interconnections show differences in the DBMS and remote system classification levels, this is a Finding.'
  desc 'fix', 'Disassociate or remove connection definitions to remote systems of differing classification levels.'
  impact 0.5
  ref 'DPMS Target Oracle Homes 11g'
  tag check_id: 'C-23524r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15656'
  tag rid: 'SV-25075r1_rule'
  tag stig_id: 'DG0171-ORACLE11'
  tag gtitle: 'DBMS interconnections'
  tag fix_id: 'F-20164r1_fix'
  tag 'documentable'
  tag responsibility: 'Database Administrator'
end
