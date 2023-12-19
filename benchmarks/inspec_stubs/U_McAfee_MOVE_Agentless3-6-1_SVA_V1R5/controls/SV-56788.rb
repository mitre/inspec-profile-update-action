control 'SV-56788' do
  title 'The McAfee MOVE AV Agentless SVA Authentication policy must be configured to communicate with the Hypervisor/vCenter server via HTTPS protocol.'
  desc 'Requiring the McAfee MOVE AV Agentless SVA to authenticate to the hypervisor over HTTPs ensures the authentication is over a secure path.'
  desc 'check', 'From the ePO server console System Tree, select "My Organization". Select the Systems tab. To show all systems in the System Tree, select "This Group and All Subgroups" from the "Preset:" drop-down list. From the list of systems, locate the asset representing the McAfee MOVE Security Virtual Appliance (SVA). Click on the system to open the System Information page. 

Click on Actions | Agent | Modify Policies on a Single System. 

For McAfee MOVE AV Agentless 3.6.1

From the "Product:" drop-down list, select “MOVE AV [Agentless] 3.6.1”. Locate "SVA" under the "Category" column and select the policy corresponding to it, found under the "Policy" column.

On the Policy Settings page, select the “General Settings” tab in McAfee MOVE Agentless 3.6.1 of the Policy Settings page, verify the "Protocol:" is set to “https”.

If the "Protocol:" is not set to “https”, this is a finding.'
  desc 'fix', 'From the ePO server console System Tree, select "My Organization". Select the Systems tab. To show all systems in the System Tree, select "This Group and All Subgroups" from the "Preset:" drop-down list. From the list of systems, locate the asset representing the McAfee MOVE Security Virtual Appliance (SVA). Click on the system to open the System Information page. 

Click on Actions | Agent | Modify Policies on a Single System. 

From the "Product:" drop-down list, select “MOVE AV [Agentless] 3.6.1”. Locate "SVA" under the "Category" column and select the policy corresponding to it, found under the "Policy" column.

On the Policy Settings page, select the “General Settings” tab in McAfee MOVE Agentless 3.6.1 of the Policy Settings page and select "https" from the drop-down list.

Click on Save.'
  impact 0.5
  ref 'DPMS Target McAfee MOVE Agentless 3.0 SVA'
  tag check_id: 'C-49407r9_chk'
  tag severity: 'medium'
  tag gid: 'V-43958'
  tag rid: 'SV-56788r2_rule'
  tag stig_id: 'AV-MOVE-SVA-002'
  tag gtitle: 'AV-MOVE-SVA-002-McAfee MOVE Agentless SVA authentication policy'
  tag fix_id: 'F-49425r7_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
