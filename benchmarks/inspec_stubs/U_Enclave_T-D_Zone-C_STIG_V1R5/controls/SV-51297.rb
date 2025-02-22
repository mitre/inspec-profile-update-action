control 'SV-51297' do
  title 'Development systems must have a firewall installed, configured, and enabled.'
  desc 'A firewall provides a line of defense against malicious attacks.   To be effective, it must be enabled and properly configured.'
  desc 'check', "Review the development images to determine whether the OS or a third party firewall has been installed, configured, and enabled.  If a firewall is not installed, configured, and enabled, this is a finding.  

If there isn't any application development occurring in the zone environment, this requirement is not applicable."
  desc 'fix', 'Install, configure, and enable either the OS or a third party firewall on the development system.'
  impact 0.5
  ref 'DPMS Target Test Enclave - Zone C'
  tag check_id: 'C-46714r3_chk'
  tag severity: 'medium'
  tag gid: 'V-39439'
  tag rid: 'SV-51297r1_rule'
  tag stig_id: 'ENTD0090'
  tag gtitle: 'ENTD0090 - A firewall is not present on the development system.'
  tag fix_id: 'F-44452r2_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
end
