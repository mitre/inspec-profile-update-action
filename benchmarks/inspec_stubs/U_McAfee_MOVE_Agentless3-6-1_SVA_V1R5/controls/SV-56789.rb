control 'SV-56789' do
  title 'The McAfee MOVE AV Agentless SVA Authentication policy must be configured to authenticate to the Hypervisor/vCenter server with user name and password.'
  desc 'Requiring the McAfee MOVE AV Agentless SVA to authenticate to the hypervisor with a username and password, coupled with HTTPs, ensures authentication is over a secure path from a valid source.'
  desc 'check', 'From the ePO server console System Tree, select "My Organization". Select the Systems tab. To show all systems in the System Tree, select "This Group and All Subgroups" from the "Preset:" drop-down list. From the list of systems, locate the asset representing the McAfee MOVE Security Virtual Appliance (SVA). Click on the system to open the System Information page. 

Click on “Actions | Agent | Modify Policies on a Single System”. From the "Product:" drop-down list, select “MOVE AV [Agentless] 3.6.1”. Locate "SVA" under the "Category" column and select the policy corresponding to it, found under the "Policy" column.

On the Policy Settings page, select the “General Settings” tab in McAfee MOVE Agentless 3.6.1 of the Policy Settings page, verify the "User:" field is populated. 

Note: The "Password:" field will appear to be blank. Since the "User:" field cannot be populated and saved without a password, however, the "Password:" field requirement can be considered compliant provided the "User:" field is validated as populated.

If the "User:" field is not populated, this is a finding.'
  desc 'fix', 'From the ePO server console System Tree, select "My Organization". Select the Systems tab. To show all systems in the System Tree, select "This Group and All Subgroups" from the "Preset:" drop-down list. From the list of systems, locate the asset representing the McAfee MOVE Security Virtual Appliance (SVA). Click on the system to open the System Information page. 

Click on “Actions | Agent | Modify Policies on a Single System”. From the "Product:" drop-down list, select “MOVE AV [Agentless]3.6.1”. Locate "SVA" under the "Category" column and select the policy corresponding to it, found under the "Policy" column.

On the Policy Settings page, select the “General Settings” tab in McAfee MOVE Agentless 3.6.1 of the Policy Settings page and populate the "User:" and "Password:" fields with a user/password combination which has authentication access to the hypervisor. Click on "Test the connection". 

Click on Save.'
  impact 0.5
  ref 'DPMS Target McAfee MOVE Agentless 3.0 SVA'
  tag check_id: 'C-49451r12_chk'
  tag severity: 'medium'
  tag gid: 'V-43959'
  tag rid: 'SV-56789r2_rule'
  tag stig_id: 'AV-MOVE-SVA-003'
  tag gtitle: 'AV-MOVE-SVA-003-McAfee MOVES SVA to hypervisor user name and password'
  tag fix_id: 'F-49563r11_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
