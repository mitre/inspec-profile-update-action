control 'SV-223572' do
  title 'IBM z/OS Policy agent must contain a policy that manages excess capacity, bandwidth, or other redundancy to limit the effects of information flooding types of Denial of Service (DoS) attacks.'
  desc 'DoS is a condition when a resource is not available for legitimate users. When this occurs, the organization either cannot accomplish its mission or must operate at degraded capacity.'
  desc 'check', 'Examine the Policy Agent policy statements. If it can be determined that there are policy statements that manages excess capacity, this is not a finding.'
  desc 'fix', 'Develop Policy application and Policy agent to manage excess capacity.'
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25245r500851_chk'
  tag severity: 'medium'
  tag gid: 'V-223572'
  tag rid: 'SV-223572r533198_rule'
  tag stig_id: 'ACF2-OS-000370'
  tag gtitle: 'SRG-OS-000142-GPOS-00071'
  tag fix_id: 'F-25233r500852_fix'
  tag 'documentable'
  tag legacy: ['V-97849', 'SV-106953']
  tag cci: ['CCI-001095']
  tag nist: ['SC-5 (2)']
end
