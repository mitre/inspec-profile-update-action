control 'SV-223793' do
  title 'The IBM z/OS Policy Agent must contain a policy that manages excess capacity, bandwidth, or other redundancy to limit the effects of information flooding types of denial-of-service (DoS) attacks.'
  desc 'DoS is a condition when a resource is not available for legitimate users. When this occurs, the organization either cannot accomplish its mission or must operate at degraded capacity.'
  desc 'check', 'Examine the Policy Agent policy statements. 

If it can be determined that there are policy statements that manages excess capacity, this is not a finding.'
  desc 'fix', 'Develop Policy application and Policy agent to manage excess capacity.'
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25466r515067_chk'
  tag severity: 'medium'
  tag gid: 'V-223793'
  tag rid: 'SV-223793r604139_rule'
  tag stig_id: 'RACF-OS-000370'
  tag gtitle: 'SRG-OS-000142-GPOS-00071'
  tag fix_id: 'F-25454r515068_fix'
  tag 'documentable'
  tag legacy: ['V-98293', 'SV-107397']
  tag cci: ['CCI-001095']
  tag nist: ['SC-5 (2)']
end
