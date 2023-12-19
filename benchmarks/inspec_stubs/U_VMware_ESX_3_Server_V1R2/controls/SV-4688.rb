control 'SV-4688' do
  title 'The rexec daemon must not be running.'
  desc 'The rexecd process provides a typically unencrypted, host-authenticated remote access service.  SSH should be used in place of this service.'
  desc 'check', 'Determine if the rexecd service is running.  If the service is running, this is a finding.'
  desc 'fix', 'Disable the rexecd service.'
  impact 0.7
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-609r2_chk'
  tag severity: 'high'
  tag gid: 'V-4688'
  tag rid: 'SV-4688r2_rule'
  tag stig_id: 'GEN003840'
  tag gtitle: 'GEN003840'
  tag fix_id: 'F-4616r2_fix'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001435']
  tag nist: ['AC-17 (8)']
end
