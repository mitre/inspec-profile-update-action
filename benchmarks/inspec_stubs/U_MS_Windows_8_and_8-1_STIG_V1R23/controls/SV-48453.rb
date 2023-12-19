control 'SV-48453' do
  title 'Infrared (IR) ports must be disabled.'
  desc 'Various connection ports can provide additional attack vectors to a system or expose sensitive information and should be limited.'
  desc 'check', 'Verify IR ports are  disabled.   View status in device manager.
If IR ports are not disabled, this is a finding.

If the system does not have IR ports, this is not applicable.'
  desc 'fix', 'Disable IR ports in device manager.'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-45118r1_chk'
  tag severity: 'medium'
  tag gid: 'V-36769'
  tag rid: 'SV-48453r2_rule'
  tag stig_id: 'WN08-MO-000013'
  tag gtitle: 'WN08-MO-000013'
  tag fix_id: 'F-41582r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
