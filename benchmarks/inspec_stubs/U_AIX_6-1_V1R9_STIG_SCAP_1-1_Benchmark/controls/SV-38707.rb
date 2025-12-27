control 'SV-38707' do
  title 'The system must not have the comsat service active.'
  desc 'The comsat daemon notifies users on incoming email.  This is an unnecessary service and is vulnerable to a flood attack.  Running unnecessary services increases the attack vector of the system.'
  desc 'fix', 'Edit /etc/inetd.conf and comment out comsat service line. Restart the inetd service.   
# refresh -s inetd'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag severity: 'medium'
  tag gid: 'V-29503'
  tag rid: 'SV-38707r1_rule'
  tag stig_id: 'GEN009190'
  tag gtitle: 'GEN009190'
  tag fix_id: 'F-33061r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001436']
  tag nist: ['AC-17 (8)']
end
