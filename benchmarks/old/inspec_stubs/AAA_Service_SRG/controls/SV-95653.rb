control 'SV-95653' do
  title 'AAA Services must be configured to place non-authenticated network access requests in the Unauthorized VLAN or the Guest VLAN with limited access.'
  desc 'Devices having an IP address that do not pass authentication can be used to attack compliant devices if they share VLANs. When devices proceed into the NAC AAA (radius) functions they must originate in the Unauthorized VLAN by default. If the device fails authentication, it should be denied IP capability and movement to other dynamic VLANs used in the NAC process flow or moved to a VLAN that has limited capability such as a Guest VLAN with internet access, but without access to production assets.'
  desc 'check', 'If AAA Services are not used for 802.1x authentication or to authenticate privileged users for device management, this is not applicable.

Verify AAA Services are configured to place non-authenticated network access requests in the Unauthorized VLAN or the Guest VLAN with limited access. If the SA has created a dynamic Unauthorized VLAN, definitions should not have an IP pool assignment. Ensure the Unauthorized VLAN is configured without IP or a Guest VLAN is defined with limited access.

If AAA Services are not configured to place non-authenticated network access requests in the Unauthorized VLAN or the Guest VLAN with limited access, this is a finding.'
  desc 'fix', 'Configure AAA Services to place non-authenticated network access requests in the Unauthorized VLAN without access to production data. Implement a NAC solution where the device remains without IP assignment if authentication fails or create a dynamic Unauthorized VLAN/Guest VLAN with limited access in AAA server. If a Guest VLAN is built, it should not have access to production data.'
  impact 0.5
  ref 'DPMS Target SRG-APP-AAA'
  tag check_id: 'C-80681r1_chk'
  tag severity: 'medium'
  tag gid: 'V-80943'
  tag rid: 'SV-95653r1_rule'
  tag stig_id: 'SRG-APP-000516-AAA-000660'
  tag gtitle: 'SRG-APP-000516-AAA-000660'
  tag fix_id: 'F-87799r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
