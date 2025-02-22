control 'SV-24982' do
  title 'Remote DBMS administration should be documented and authorized or disabled.'
  desc 'Remote administration may expose configuration and sensitive data to unauthorized viewing during transit across the network or allow unauthorized administrative access to the DBMS to remote users.'
  desc 'check', 'Review the System Security Plan for authorization, assignments and usage procedures for remote DBMS administration.

If remote administration of the DBMS is not documented or poorly documented, this is a Finding.

If remote administration of the DBMS is not authorized and not disabled, this is a Finding.'
  desc 'fix', 'Disable remote administration of the DBMS where not required.

Where remote administration of the DBMS is required, develop, document and implement policy and procedures on its use.

Assign remote administration privileges to IAO-authorized personnel only.

Document assignments in the System Security Plan.'
  impact 0.5
  ref 'DPMS Target Oracle Homes 11g'
  tag check_id: 'C-19408r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15651'
  tag rid: 'SV-24982r1_rule'
  tag stig_id: 'DG0157-ORACLE11'
  tag gtitle: 'DBMS remote administration'
  tag fix_id: 'F-19561r1_fix'
  tag 'documentable'
  tag responsibility: 'Database Administrator'
end
