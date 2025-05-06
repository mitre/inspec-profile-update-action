control 'SV-95145' do
  title 'The Bromium Enterprise Controller (BEC) must be configured to immediately disconnect or disable remote access to the BEC.'
  desc 'Without the ability to immediately disconnect or disable remote access, an attack or other compromise would not be immediately stopped.

Applications must have the capability to immediately disconnect current users remotely accessing the information system and/or disable further remote access. The speed of disconnect or disablement varies based on the criticality of missions/business functions and the need to eliminate immediate or future remote access to organizational information systems.

The remote access application (e.g., VPN client) may implement features, such as automatic disconnect (or user-initiated disconnect) in case of adverse information based on an indicator of compromise or attack.'
  desc 'check', 'Inspect the BEC user settings for a role with no privileges and a group that is tied to that role. 

1. From the management console, click on the arrow next to "Settings".
2. Click on "Roles".
3. Identify and select the role that has no privileges assigned to it. 
4. Inspect the "Role" settings to ensure that a group has been assigned. 

If the BEC is not configured to immediately disconnect or disable remote access to the information system, this is a finding.'
  desc 'fix', 'Disable access for the user account by assigning a role with zero privileges enabled. A role that has zero privileges assigned to it must exist, along with a group that is assigned to the role. 

1. From the management console, click on the arrow next to "Settings".
2. Click on "Users".
3. Select the user that has been identified for disabling.
4. Add the user to the group that is associated with the role that carries zero privileges.
5. Delete/remove all other groups for that user.
6. Click "Save".'
  impact 0.5
  ref 'DPMS Target Bromium Secure Platform'
  tag check_id: 'C-80113r1_chk'
  tag severity: 'medium'
  tag gid: 'V-80441'
  tag rid: 'SV-95145r1_rule'
  tag stig_id: 'BROM-00-000685'
  tag gtitle: 'SRG-APP-000316'
  tag fix_id: 'F-87247r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002322']
  tag nist: ['AC-17 (9)']
end
