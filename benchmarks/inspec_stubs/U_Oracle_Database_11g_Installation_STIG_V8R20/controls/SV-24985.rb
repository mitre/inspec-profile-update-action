control 'SV-24985' do
  title 'DBMS remote administration should be audited.'
  desc 'When remote administration is available, the vulnerability to attack for administrative access is increased. An audit of remote administrative access provides additional means to discover suspicious activity and to provide accountability for administrative actions completed by remote users.'
  desc 'check', 'Review settings for actions taken during remote administration sessions.

If auditing of remote administration sessions and actions is not enabled, this is a Finding.

If audit logs do not include all actions taken by database administrators during remote sessions, this is a Finding.

Actions should be tied to a specific user.'
  desc 'fix', 'Develop, document and implement policy and procedures for remote administration auditing.

Configure the DBMS to provide an audit trail for remote administrative sessions.

Include all actions taken by database administrators during remote sessions.

Actions should be tied to a specific user.'
  impact 0.5
  ref 'DPMS Target Oracle Homes 11g'
  tag check_id: 'C-20343r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15652'
  tag rid: 'SV-24985r1_rule'
  tag stig_id: 'DG0158-ORACLE11'
  tag gtitle: 'DBMS remote administration audit'
  tag fix_id: 'F-16165r1_fix'
  tag 'documentable'
  tag responsibility: 'Database Administrator'
end
