control 'SV-26021' do
  title 'The audit system must alert the SA in the event of an audit processing failure.'
  desc 'An accurate and current audit trail is essential for maintaining 
a record of system activity. If the system fails, the SA must be notified and must take prompt 
action to correct the problem.

Minimally, the system must log this event and the SA will receive this notification during the 
daily system log review. If feasible, active alerting (such as email or paging) should be 
employed consistent with the site’s established operations management systems and procedures.'
  desc 'check', 'Determine if the audit system is configured to alert the SA in the event of an audit processing failure. If it is not, this is a finding.'
  desc 'fix', 'Configure the audit system to alert the SA in the event of an audit processing failure.'
  impact 0.3
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-29207r1_chk'
  tag severity: 'low'
  tag gid: 'V-22374'
  tag rid: 'SV-26021r1_rule'
  tag stig_id: 'GEN002719'
  tag gtitle: 'GEN002719'
  tag fix_id: 'F-26227r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECAT-1'
  tag cci: ['CCI-000139']
  tag nist: ['AU-5 a']
end
