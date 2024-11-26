control 'SV-56791' do
  title 'The McAfee MOVE AV Agentless SVA Scan Settings policy must be configured to cache scan results for files up to a file size of 1 MB.'
  desc 'While enabling cache in the McAfee MOVE AV Agentless SVA will enable a more effective performance when scanning virtual machines, the file size of cached items needs to be restricted in order to prevent excessively large files from being cached, which would have a negative impact on performance.'
  desc 'check', 'From the ePO server console System Tree, select "My Organization". Select the Systems tab. To show all systems in the System Tree, select "This Group and All Subgroups" from the "Preset:" drop-down list. From the list of systems, locate the asset representing the McAfee MOVE Security Virtual Appliance (SVA). Click on the system to open the System Information page. 

Click on “Actions | Agent | Modify Policies on a Single System”. From the "Product:" drop-down list, select “MOVE AV [Agentless] 3.6.1”. Locate "SVA" under the "Category" column and select the policy corresponding to it, found under the "Policy" column.  

In the Scan Settings tab of the Policy Settings page, verify the "Cache scan result of file size up to (MB):" is configured for "1".

If the "Cache scan result of file size up to (MB):" is not configured to "1", this is a finding.'
  desc 'fix', 'From the ePO server console System Tree, select "My Organization". Select the Systems tab. To show all systems in the System Tree, select "This Group and All Subgroups" from the "Preset:" drop-down list. From the list of systems, locate the asset representing the McAfee MOVE Security Virtual Appliance (SVA). Click on the system to open the System Information page. 

Click on Actions | Agent | Modify Policies on a Single System. From the "Product:" drop-down list, select MOVE AV [Agentless] 3.6.1. Locate "SVA" under the "Category" column and select the policy corresponding to it, found under the "Policy" column.

In the Scan Settings tab of the Policy Settings page, populate the "Cache scan result of file size up to (MB):" with a value of "1"

Click on Save.'
  impact 0.5
  ref 'DPMS Target McAfee MOVE Agentless 3.0 SVA'
  tag check_id: 'C-49453r6_chk'
  tag severity: 'medium'
  tag gid: 'V-43961'
  tag rid: 'SV-56791r2_rule'
  tag stig_id: 'AV-MOVE-SVA-005'
  tag gtitle: 'AV-MOVE-SVA-005-McAfee MOVE SVA Scan Cache file size'
  tag fix_id: 'F-49565r3_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
