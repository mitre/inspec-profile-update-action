control 'SV-242582' do
  title "The Cisco ISE must be configured to notify the user before proceeding with remediation of the user's endpoint device when automated remediation is used."
  desc 'Notification will let the user know that installation is in progress and may take a while. This notice may deter the user from disconnecting and retrying the connection before the remediation is completed. Premature disconnections may increase network demand and frustrate the user.

Note: This policy does not require remediation to be performed by the Cisco ISE, but will apply if remediation services are used.'
  desc 'check', 'Verify that each requirement used has a message to display. 

1. Navigate to Work Centers >> Posture >> Posture Policy.
2. Make a note of each "Requirement" tied to an enabled Posture Policy.
3. Navigate to Work Centers >> Posture >> Policy Elements >> Requirements.
4. Verify that each requirement noted has a message in the "Message Shown to Agent User" box. 

If a requirement that is used does not have a message, this is a finding.'
  desc 'fix', 'Configure a message prior to remediation:

1. Navigate to Work Centers >> Posture >> Policy Elements >> Requirements.
2. On the requirements under "Remediation Actions", define a message in the "Message Shown to Agent User".
3. Choose "Done".
4. Choose "Save".'
  impact 0.3
  ref 'DPMS Target Cisco ISE NAC'
  tag check_id: 'C-45857r714054_chk'
  tag severity: 'low'
  tag gid: 'V-242582'
  tag rid: 'SV-242582r714056_rule'
  tag stig_id: 'CSCO-NC-000080'
  tag gtitle: 'SRG-NET-000015-NAC-000070'
  tag fix_id: 'F-45814r714055_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
