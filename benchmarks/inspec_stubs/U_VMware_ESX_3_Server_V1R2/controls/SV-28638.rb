control 'SV-28638' do
  title 'TCP backlog queue sizes must be set appropriately.'
  desc 'To provide some mitigation to TCP DoS attacks, the TCP backlog queue sizes must be set to at least 1280 or in accordance with product-specific guidelines.'
  desc 'check', "Determine if the system's TCP backlog queue size is set to 1280 or higher.  If it is not, this is a finding."
  desc 'fix', "Set the system's TCP backlog queue size to 1280 or greater."
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-28893r1_chk'
  tag severity: 'medium'
  tag gid: 'V-23741'
  tag rid: 'SV-28638r1_rule'
  tag stig_id: 'GEN003601'
  tag gtitle: 'GEN003601'
  tag fix_id: 'F-25915r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
end
