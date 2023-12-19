control 'SV-77503' do
  title 'The McAfee VirusScan Enterprise for Linux 1.9.x/2.0.x On-Access scanner must be configured to scan all file types.'
  desc 'When scanning for malware, excluding specific file types will increase the risk of a malware-infected file going undetected. By configuring anti-virus software to scan all file types, the scanner has a higher success rate at detecting and eradicating malware.'
  desc 'check', 'From the ePO server console System Tree, select "My Organization". Select the "Systems" tab. To show all systems in the System Tree, select "This Group and All Subgroups" from the "Preset:" drop-down list.

From the list of systems, locate the asset representing the Linux system being reviewed. Click on the system to open the System Information page. 

Click on Actions >> Agent >> Modify Policies on a Single System.

From the "Product:" drop-down list, select "VirusScan Enterprise for Linux 1.9.x/2.0.x".

From the "Policy" column, click on the policy for the "On-Access Scanning Policy".

In the "Detections" tab, next to "What to scan:", verify the radio button for "All files" is selected.

If the radio button for "What to scan: All files" is not selected, this is a finding.'
  desc 'fix', 'From the ePO server console System Tree, select "My Organization". Select the "Systems" tab. To show all systems in the System Tree, select "This Group and All Subgroups" from the "Preset:" drop-down list.

From the list of systems, locate the asset representing the Linux system being reviewed. Click on the system to open the System Information page. 

Click on Actions >> Agent >> Modify Policies on a Single System.

From the "Product:" drop-down list, select "VirusScan Enterprise for Linux 1.9.x/2.0.x".

From the "Policy" column, click on the policy for the "On-Access Scanning Policy".

In the "Detections" tab, next to "What to scan:", select the radio button for "All files".

Click "Save".'
  impact 0.5
  ref 'DPMS Target McAfee VSEL Managed Client'
  tag check_id: 'C-63765r1_chk'
  tag severity: 'medium'
  tag gid: 'V-63013'
  tag rid: 'SV-77503r1_rule'
  tag stig_id: 'DTAVSEL-010'
  tag gtitle: 'SRG-APP-000279'
  tag fix_id: 'F-68931r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001243']
  tag nist: ['SI-3 c 2']
end
