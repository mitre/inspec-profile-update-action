control 'SV-77519' do
  title 'The McAfee VirusScan Enterprise for Linux 1.9.x/2.0.x On-Access scanner must be configured to allow access to files if scanning times out.'
  desc 'Anti-virus software is the most commonly used technical control for malware threat mitigation. Real-time scanning of files as they are read from disk is a crucial first line of defense from malware attacks.'
  desc 'check', 'From the ePO server console System Tree, select "My Organization". Select the "Systems" tab. To show all systems in the System Tree, select "This Group and All Subgroups" from the "Preset:" drop-down list.

From the list of systems, locate the asset representing the Linux system being reviewed. Click on the system to open the System Information page. 

Click on Actions >> Agent >> Modify Policies on a Single System.

From the "Product:" drop-down list, select "VirusScan Enterprise for Linux 1.9.x/2.0.x".

From the "Policy" column, click on the policy for the "On-Access Scanning Policy".

In the "Actions" tab, verify the "If scanning times out: Allow access to the file" radio button is selected.

If the "If scanning times out: Allow access to the file" radio button is not selected, this is a finding.'
  desc 'fix', 'From the ePO server console System Tree, select "My Organization". Select the "Systems" tab. To show all systems in the System Tree, select "This Group and All Subgroups" from the "Preset:" drop-down list.

From the list of systems, locate the asset representing the Linux system being reviewed. Click on the system to open the System Information page. 

Click on Actions >> Agent >> Modify Policies on a Single System.

From the "Product:" drop-down list, select "VirusScan Enterprise for Linux 1.9.x/2.0.x".

From the "Policy" column, click on the policy for the "On-Access Scanning Policy".

In the "Actions" tab, select the "If scanning times out: Allow access to the file" radio button.

Click "Save".'
  impact 0.5
  ref 'DPMS Target McAfee VSEL Managed Client'
  tag check_id: 'C-63781r1_chk'
  tag severity: 'medium'
  tag gid: 'V-63029'
  tag rid: 'SV-77519r1_rule'
  tag stig_id: 'DTAVSEL-018'
  tag gtitle: 'SRG-APP-000279'
  tag fix_id: 'F-68947r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001243']
  tag nist: ['SI-3 c 2']
end
