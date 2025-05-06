control 'SV-26101' do
  title 'The rexecd service must not be installed.'
  desc 'The rexecd process provides a typically unencrypted, host-authenticated remote access service.  SSH should be used in place of this service.'
  desc 'check', 'Determine if the rexecd service is installed.  If it is, this is a finding.'
  desc 'fix', 'Uninstall the rexecd service from the system.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-29266r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22434'
  tag rid: 'SV-26101r1_rule'
  tag stig_id: 'GEN003845'
  tag gtitle: 'GEN003845'
  tag fix_id: 'F-26284r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000305']
  tag nist: ['CM-7 (2)']
end
