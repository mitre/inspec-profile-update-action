control 'SV-242602' do
  title 'The Cisco ISE must be configured to dynamically apply restricted access of endpoints that are granted access using MAC Authentication Bypass (MAB). This is required for compliance with C2C Step 4.'
  desc 'MAB can be defeated by spoofing the MAC address of a valid device. MAB enables port-based access control using the MAC address of the endpoint. A MAB-enabled port can be dynamically enabled or disabled based on the MAC address of the device that connects to it.

NPE devices that can support PKI or an allowed authentication type must use PKI. MAB may be used for NPE that cannot support an approved device authentication. Non-entity endpoints include IoT devices, VOIP phone, and printer.'
  desc 'check', 'If DoD is not at C2C Step 4 or higher, this is not a finding.

Verify that the authorization policies for devices granted access via MAB will have restricted access. 

1. Navigate to Work Centers >> Network Access >> Policy Sets.
2. Choose ">" on the applicable policy set.
3. Expand the Authorization Policy.
4. Make a note of the result/results on each authorization policy for MAB.
5. Navigate to Policy >> Policy Elements >> Results >> Authorization.
6. Expand "Authorization".
7. Choose "Authorization Profiles".
8. View the Standard Authorization Profile/Profiles noted above to ensure that a restricted VLAN, Access Control List, Scalable Group Tag, or any combination of these is used to restrict access.

If a VLAN is the only thing being applied to the session and the VLAN has an ACL on the layer 3 interface, this is not a finding. 

If there is not a restriction on an MAB authorization policy, this is a finding.'
  desc 'fix', 'Configure the authorization policies for devices granted access via MAB to have restricted access.

1. Navigate to Work Centers >> Network Access >> Policy Sets.
2. Choose ">" on the applicable policy set.
3. Expand the "Authorization Policy".
4. Add a restricted VLAN, Access Control List, Scalable Group Tag, or any combination of these that are used to restrict access under results.
5. Repeat this for each authorization policy that devices connecting via MAB will use.
6. Choose "Save".'
  impact 0.5
  ref 'DPMS Target Cisco ISE NAC'
  tag check_id: 'C-45877r812785_chk'
  tag severity: 'medium'
  tag gid: 'V-242602'
  tag rid: 'SV-242602r855859_rule'
  tag stig_id: 'CSCO-NC-000280'
  tag gtitle: 'SRG-NET-000343-NAC-001470'
  tag fix_id: 'F-45834r714115_fix'
  tag 'documentable'
  tag cci: ['CCI-001958']
  tag nist: ['IA-3']
end
