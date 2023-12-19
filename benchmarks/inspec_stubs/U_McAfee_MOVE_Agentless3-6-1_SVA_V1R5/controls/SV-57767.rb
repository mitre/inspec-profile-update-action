control 'SV-57767' do
  title 'The McAfee MOVE AV Agentless Scan policy must be configured to enforce a maximum On-Access Scan timeout of no less than 45 seconds.'
  desc 'This setting configures the amount of time to wait for a scan to complete, in seconds. The default setting is 45 seconds. Typically, file scans are very fast. However, file scans may take longer time due to large file size, file type, or heavy load on the offload scan server. In such cases that the file scan takes longer than the scan timeout limit, the file access is allowed and a scan timeout event is generated. Setting the timeout too low may result in scans of a file terminating before the scan is completed, resulting in malware potentially going undetected.'
  desc 'check', 'From the ePO server console System Tree, select "My Organization". Select the Systems tab. To show all systems in the System Tree, select "This Group and All Subgroups" from the "Preset:" drop-down list. From the list of systems, locate the asset representing the McAfee MOVE Security Virtual Appliance (SVA). Click on the system to open the System Information page. 

Click on Actions | Agent | Modify Policies on a Single System. From the "Product:" drop-down list, select MOVE AV [Agentless] 3.6.1. Locate "Scan" under the "Category" column and select the policy corresponding to it, found under the "Policy" column.

In the General tab of the Policy Settings page, next to the "On-Access Scan timeout:", verify the "Enforce a maximum scanning time for all files (On-Access Scans only)" checkbox is selected.
Verify the "On-Access Scan timeout: Maximum scan time (seconds):" has a value of 45 or more.

If the checkbox for "On-Access Scan timeout: Enforce a maximum scanning time for all files (On-Access Scans only)"is not selected and/or the "On-Access Scan timeout: Maximum scan time (seconds):" does not have a value of 45 or more, this is a finding.'
  desc 'fix', 'From the ePO server console System Tree, select "My Organization". Select the Systems tab. To show all systems in the System Tree, select "This Group and All Subgroups" from the "Preset:" drop-down list. From the list of systems, locate the asset representing the McAfee MOVE Security Virtual Appliance (SVA). Click on the system to open the System Information page. 

Click on Actions | Agent | Modify Policies on a Single System. From the "Product:" drop-down list, select MOVE AV [Agentless] 3.6.1. Locate "Scan" under the "Category" column and select the policy corresponding to it, found under the "Policy" column.

In the General tab of the Policy Settings page, next to the "On-Access Scan timeout:", select the checkbox for "Enforce a maximum scanning time for all files (On-Access Scans only)".
In the "On-Access Scan timeout: Maximum scan time (seconds):" place a value of 45 or more.

Click on Save.'
  impact 0.5
  ref 'DPMS Target McAfee MOVE Agentless 3.0 SVA'
  tag check_id: 'C-49456r5_chk'
  tag severity: 'medium'
  tag gid: 'V-44933'
  tag rid: 'SV-57767r2_rule'
  tag stig_id: 'AV-MOVE-SVA-102'
  tag gtitle: 'AV-MOVE-SVA-102-McAfee MOVE On-Access scan timeout'
  tag fix_id: 'F-49568r3_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
