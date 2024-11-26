control 'SV-242587' do
  title 'The Cisco ISE must be configured so client machines do not communicate with other network devices in the DMZ or subnet except as needed to perform an access client assessment or to identify themselves. This is required for compliance with C2C Step 2.'
  desc 'Devices not compliant with DoD secure configuration policies are vulnerable to attack. Allowing these systems to connect presents a danger to the enclave.

This requirement gives the option to configure for automated remediation and/or manual remediation. Detailed record must be passed to the remediation server for action. Alternatively, the details can be passed in a notice to the user for action. The device status will be updated on the network access server/authentication server so that further access attempts are denied. The Cisco ISE should have policy assessment mechanisms with granular control to distinguish between access restrictions based on the criticality of the software or setting failure.

Configure reminders to be sent to the user and the SA periodically or at a minimum, each time a policy assessment is performed. This can be done via the Cisco ISE or any notification system.

The failure must also be used to update the HBSS agent.'
  desc 'check', 'If DoD is not at C2C Step 2 or higher, this is not a finding.
If not required by the NAC SSP, this is not a finding.

Verify the authorization policy will prevent intra-remediation VLAN communication.

1. Navigate to Policy >> Policy Elements >> Results.
2. Choose ">" on the applicable policy set.
3. Expand the Authorization Policy.
4. Verify that a rule with the condition "Session-PostureStatus EQUALS NonCompliant" or an authorization policy for remediation is present making a note of the authorization profile.
5. Navigate to Policy >> Policy Elements >> Results >> Authorization >> Authorization Profiles >> Authorization profile noted above.
6. Ensure the result that is used will result in lateral traffic for that VLAN will be restricted by a private VLAN, dACL, ACL, SGT, or any combination.
7. If a private VLAN is used, review the switch configuration to confirm it is a private VLAN.

If there is not an authorization policy for NonCompliant clients or remediation, this is a finding.

If the authorization policy does not prevent intra-remediation VLAN communication, this is a finding.'
  desc 'fix', 'If required by the NAC SSP, configure the remediation authorization policy to prevent intra-remediation VLAN communication.

1. Navigate to Work Centers >> Network Access >> Policy Sets.
2. Choose ">" on the applicable policy set.
3. Expand the Authorization Policy.
4. Locate the authorization policy with the "Session-PostureStatus EQUALS NonCompliant" or authorization policy for remediation access.
5. Configure the result to block intra-VLAN communication (Private VLAN, dACL, ACL, or SGT).
6. Choose "Save".'
  impact 0.5
  ref 'DPMS Target Cisco ISE NAC'
  tag check_id: 'C-45862r812755_chk'
  tag severity: 'medium'
  tag gid: 'V-242587'
  tag rid: 'SV-242587r812756_rule'
  tag stig_id: 'CSCO-NC-000130'
  tag gtitle: 'SRG-NET-000015-NAC-000130'
  tag fix_id: 'F-45819r803547_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
