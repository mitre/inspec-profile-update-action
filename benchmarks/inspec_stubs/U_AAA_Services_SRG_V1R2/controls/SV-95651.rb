control 'SV-95651' do
  title 'AAA Services must be configured to use IP segments separate from production VLAN IP segments.'
  desc 'When policy assessment and remediation have been implemented and the advanced AAA server dynamic VLAN is misconfigured, logical separation of the production VLAN may not be assured.

Non-trusted resources are resources that are not authenticated in a NAC solution implementing only the authentication component of NAC. Non-trusted resources could become resources that have been authenticated but have not had a successful policy assessment when the automated policy assessment component has been implemented.'
  desc 'check', 'If AAA Services are not used for 802.1x authentication or to authenticate privileged users for device management, this is not applicable.

Verify AAA Services are configured to use IP segments separate from production VLAN IP segments. 

If AAA Services are not configured to use IP segments separate from production VLAN IP segments, this is a finding.'
  desc 'fix', 'Configure AAA Services to use IP segments separate from production VLAN IP segments.'
  impact 0.5
  ref 'DPMS Target SRG-APP-AAA'
  tag check_id: 'C-80679r1_chk'
  tag severity: 'medium'
  tag gid: 'V-80941'
  tag rid: 'SV-95651r1_rule'
  tag stig_id: 'SRG-APP-000516-AAA-000650'
  tag gtitle: 'SRG-APP-000516-AAA-000650'
  tag fix_id: 'F-87797r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
