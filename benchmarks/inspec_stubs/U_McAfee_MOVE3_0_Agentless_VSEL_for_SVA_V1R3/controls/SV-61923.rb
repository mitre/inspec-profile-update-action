control 'SV-61923' do
  title 'The McAfee VirusScan Enterprise for Linux 1.9.0 On-Access scanner maximum scan time must not be less than 45 seconds.'
  desc 'When antivirus software is not configured to limit the amount of time spent trying to scan a file, the total effectiveness of the antivirus software, and performance on the system being scanned, will be degraded. By limiting the amount of time the antivirus software uses when scanning a file, the scan will be able to complete in a timely manner.'
  desc 'check', 'From the ePO server console System Tree, select "My Organization". Select the "Systems" tab. To show all systems in the System Tree, select "This Group and All Subgroups" from the "Preset:" drop-down list. From the list of systems, locate the asset representing the McAfee MOVE Security Virtual Appliance (SVA). Click on the system to open the System Information page. 

Click on Actions | Agent | Modify Policies on a Single System. From the "Product:" drop-down list, select "VirusScan Enterprise for Linux 1.9.0". From the "Policy" column, click on the policy for the "On-Access Scanning Policy".

In the "General" tab, next to "Maximum Scan Time:", verify the check box for "Enforce maximum scanning time for all files" has been selected. Verify the "Maximum scan time (seconds):" is configured to 45 or more.

If the check box for "Maximum Scan Time: Enforce maximum scanning time for all files" is not selected, this is a finding.
If the "Maximum Scan Time (seconds):" is not configured to 45 or more, this is a finding.

If both the "Maximum Scan Time:" setting for "Enforce maximum scanning time for all files" has a check in the check box and the "Maximum Scan Time:" setting for "Maximum scan time (seconds):" is configured to 45 or more, this is not a finding.'
  desc 'fix', 'From the ePO server console System Tree, select "My Organization". Select the "Systems" tab. To show all systems in the System Tree, select "This Group and All Subgroups" from the "Preset:" drop-down list. From the list of systems, locate the asset representing the McAfee MOVE Security Virtual Appliance (SVA). Click on the system to open the System Information page. 

Click on Actions | Agent | Modify Policies on a Single System. From the "Product:" drop-down list, select "VirusScan Enterprise for Linux 1.9.0". From the "Policy" column, click on the policy for the "On-Access Scanning Policy".

In the "General" tab, next to "Maximum Scan Time:", select the check box for "Enforce maximum scanning time for all files". Configure the "Maximum scan time (seconds):" to 45 or more.

Click Save.'
  impact 0.5
  ref 'DPMS Target McAfee VirusScan Enterprise for Linux (VSEL) 1.9'
  tag check_id: 'C-49439r3_chk'
  tag severity: 'medium'
  tag gid: 'V-49037'
  tag rid: 'SV-61923r1_rule'
  tag stig_id: 'DTAVSEL-011'
  tag gtitle: 'DTAVSEL-011-McAfee VSEL for SVA OAS maximum scan time'
  tag fix_id: 'F-49550r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
