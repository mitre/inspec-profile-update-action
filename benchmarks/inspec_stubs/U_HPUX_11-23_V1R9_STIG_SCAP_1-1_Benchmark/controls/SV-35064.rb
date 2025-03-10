control 'SV-35064' do
  title 'Inetd and xinetd must be disabled or removed if no network services utilizing them are enabled.'
  desc 'Unnecessary services should be disabled to decrease the attack surface of the system.'
  desc 'fix', 'Remove or disable the inetd startup scripts and kill the service.'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag severity: 'medium'
  tag gid: 'V-12005'
  tag rid: 'SV-35064r1_rule'
  tag stig_id: 'GEN003700'
  tag gtitle: 'GEN003700'
  tag fix_id: 'F-31882r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000305']
  tag nist: ['CM-7 (2)']
end
