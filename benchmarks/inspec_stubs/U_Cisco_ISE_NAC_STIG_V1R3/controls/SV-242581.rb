control 'SV-242581' do
  title 'For endpoints that require automated remediation, the Cisco ISE must be configured to redirect endpoints to a logically separate VLAN for remediation services. This is required for compliance with C2C Step 4.'
  desc 'Automated and manual procedures for remediation for critical security updates will be managed differently. Continuing to assess and remediate endpoints with risks that could endanger the network could impact network usage for all users. This isolation prevents traffic from flowing with traffic from endpoints that have been fully assessed and authorized.

Unauthenticated devices must not be allowed to connect to remediation services.'
  desc 'check', 'If DoD is not at C2C Step 4 or higher, this is not a finding.
If not required by the NAC SSP, this is not a finding.

Verify that the authorization policies for "Posture NonCompliant" have a result that will assign the remediation VLAN. 

1. Work Centers >> Network Access >> Policy Sets.
2. Choose ">" on the desired policy set.
3. Expand Authorization Policy.
4. Scan for Authorization policies with "Posture NonCompliant" condition.
5. Verify the result assigned to the authorization policy will assign the remediation VLAN. 

If the result is the remediation VLAN, this is not a finding.

If posture is not mandated by the Information System Security Manager (ISSM), this is not a finding.'
  desc 'fix', 'If required by the NAC SSP, configure the "Posture NonCompliant" authorization policy so that the result that will assign the remediation VLAN.

1. Work Centers >> Network Access >> Policy Sets.
2. Choose ">" on the desired policy set.
3. Expand Authorization Policy.
4. Create an authorization policy for "Posture NonCompliant".
5. Assign the remediation VLAN result.'
  impact 0.5
  ref 'DPMS Target Cisco ISE NAC'
  tag check_id: 'C-45856r812743_chk'
  tag severity: 'medium'
  tag gid: 'V-242581'
  tag rid: 'SV-242581r812744_rule'
  tag stig_id: 'CSCO-NC-000070'
  tag gtitle: 'SRG-NET-000015-NAC-000040'
  tag fix_id: 'F-45813r803529_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
