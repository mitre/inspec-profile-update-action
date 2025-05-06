control 'SV-57827' do
  title 'The McAfee MOVE AV Agentless Scan policy must be configured to scan inside archives.'
  desc 'Malware is often packaged within an archive. In addition, archives might have other archives within. Not scanning archive files introduces the risk of infected files being introduced into the environment.'
  desc 'check', 'Note: If the regularly scheduled scan includes the scanning of archive files, this requirement can alternatively be not configured and marked as Not Applicable.

If configuring this setting causes performance degradation on virtual machines, this can be downgraded to a CAT III.

From the ePO server console System Tree, select "My Organization". Select the "Systems" tab. To show all systems in the System Tree, select "This Group and All Subgroups" from the "Preset:" drop-down list. From the list of systems, locate the asset representing the McAfee MOVE Security Virtual Appliance (SVA). 

Click on the system to open the System Information page.
Click on Actions >> Agent >> Modify Policies on a Single System. 

From the "Product:" drop-down list, select "MOVE AV [Agentless] 3.6.1". Locate "Scan" under the "Category" column and select the policy corresponding to it, found under the "Policy" column.

In the "Scan Items" tab of the Policy Settings, next to the "Compressed files:" Verify the checkbox for "Scan inside archives (e.g., .ZIP)" is selected.

If the checkbox for "Compressed files: Scan inside archives (e.g., .ZIP)" is not selected, this is a finding.'
  desc 'fix', 'From the ePO server console System Tree, select "My Organization". Select the Systems tab. To show all systems in the System Tree, select "This Group and All Subgroups" from the "Preset:" drop-down list. From the list of systems, locate the asset representing the McAfee MOVE Security Virtual Appliance (SVA). Click on the system to open the System Information page. 

Click on Actions | Agent | Modify Policies on a Single System. From the "Product:" drop-down list, select "MOVE AV [Agentless] 3.6.1". Locate "Scan" under the "Category" column and select the policy corresponding to it, found under the "Policy" column.

In the Scan Items tab of the Policy Settings, next to the "Compressed files:", select the check box for "Scan inside archives (e.g., .ZIP)".

Click on Save.'
  impact 0.5
  ref 'DPMS Target McAfee MOVE Agentless 3.0 SVA'
  tag check_id: 'C-49461r8_chk'
  tag severity: 'medium'
  tag gid: 'V-44993'
  tag rid: 'SV-57827r3_rule'
  tag stig_id: 'AV-MOVE-SVA-107'
  tag gtitle: 'AV-MOVE-SVA-107-McAfee MOVE scan inside archives policy'
  tag fix_id: 'F-49573r5_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
