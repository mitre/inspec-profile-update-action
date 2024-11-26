control 'SV-77505' do
  title 'The McAfee VirusScan Enterprise for Linux 1.9.x/2.0.x On-Access scanner maximum scan time must not be less than 45 seconds.'
  desc 'When anti-virus software is not configured to limit the amount of time spent trying to scan a file, the total effectiveness of the anti-virus software, and performance on the system being scanned, will be degraded. By limiting the amount of time the anti-virus software uses when scanning a file, the scan will be able to complete in a timely manner.'
  desc 'check', 'From the ePO server console System Tree, select "My Organization". Select the "Systems" tab. To show all systems in the System Tree, select "This Group and All Subgroups" from the "Preset:" drop-down list.

From the list of systems, locate the asset representing the Linux system being reviewed. Click on the system to open the System Information page. 

Click on Actions >> Agent >> Modify Policies on a Single System.

From the "Product:" drop-down list, select "VirusScan Enterprise for Linux 1.9.x/2.0.x".

From the "Policy" column, click on the policy for the "On-Access Scanning Policy".

In the "General" tab, next to "Maximum Scan Time:", verify the check box for "Enforce maximum scanning time for all files" has been selected.

Verify the "Maximum scan time (seconds):" is configured to 45 or more.

If the check box for "Maximum Scan Time: Enforce maximum scanning time for all files" is not selected, this is a finding. 

If the "Maximum Scan Time (seconds):" is not configured to 45 or more, this is a finding.

If both the "Maximum Scan Time:" setting for "Enforce maximum scanning time for all files" has a check in the check box and the "Maximum Scan Time:" setting for "Maximum scan time (seconds):" is configured to 45 or more, this is not a finding.'
  desc 'fix', 'From the ePO server console System Tree, select "My Organization". Select the "Systems" tab. To show all systems in the System Tree, select "This Group and All Subgroups" from the "Preset:" drop-down list.

From the list of systems, locate the asset representing the Linux system being reviewed. Click on the system to open the System Information page. 

Click on Actions >> Agent >> Modify Policies on a Single System.

From the "Product:" drop-down list, select "VirusScan Enterprise for Linux 1.9.x/2.0.x".

From the "Policy" column, click on the policy for the "On-Access Scanning Policy".

In the "General" tab, next to "Maximum Scan Time:", select the check box for "Enforce maximum scanning time for all files". Configure the "Maximum scan time (seconds):" to 45 or more.

Click "Save".'
  impact 0.5
  ref 'DPMS Target McAfee VSEL Managed Client'
  tag check_id: 'C-63767r1_chk'
  tag severity: 'medium'
  tag gid: 'V-63015'
  tag rid: 'SV-77505r1_rule'
  tag stig_id: 'DTAVSEL-011'
  tag gtitle: 'SRG-APP-000279'
  tag fix_id: 'F-68933r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001243']
  tag nist: ['SI-3 c 2']
end
