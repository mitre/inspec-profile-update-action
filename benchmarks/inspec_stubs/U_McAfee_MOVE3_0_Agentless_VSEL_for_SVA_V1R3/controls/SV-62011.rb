control 'SV-62011' do
  title 'The McAfee VirusScan Enterprise for Linux 1.9.0 On Demand scanner must be configured to include all local drives and their sub-directories.'
  desc 'When scanning for malware, excluding specific file types will increase the risk of a malware-infected file going undetected. By configuring antivirus software to scan all file types, the scanner has a higher success rate at detecting and eradicating malware.'
  desc 'check', 'From the ePO server console System Tree, select "My Organization". Select the "Systems" tab. To show all systems in the System Tree, select "This Group and All Subgroups" from the "Preset:" drop-down list. From the list of systems, locate the asset representing the McAfee MOVE Security Virtual Appliance (SVA). Click on the system to open the System Information page. 

Click on Actions | Agent | Modify Tasks on a Single System.  

From the list of available tasks in the "Task Name" column, with the assistance of the ePO SA, identify the weekly On Demand scan client task. 

If a weekly On Demand scan client task does not exist, this is a finding.

For the designated weekly On Demand scan client task, verify the "Task Type" is listed as "On Demand Scan".
Verify the "Status" is listed as "Enabled".
Under the "Task Name" column, click on the link for the designated task to review the task properties.

In the "Where" tab, verify the "Specify where scanning will take place" field is populated with all local drives.
Next to "Scan options", verify the checkbox for "Include sub-directories" is selected.

If the "Specify where scanning will take place" field is not populated with all local drives, this is a finding.
If the "Include sub-directories" is not selected, this is a finding.'
  desc 'fix', 'From the ePO server console System Tree, select "My Organization". Select the "Systems" tab. To show all systems in the System Tree, select "This Group and All Subgroups" from the "Preset:" drop-down list. From the list of systems, locate the asset representing the McAfee MOVE Security Virtual Appliance (SVA). Click on the system to open the System Information page. 

Click on Actions | Agent | Modify Tasks on a Single System.  

From the list of available tasks in the "Task Name" column, with the assistance of the ePO SA, identify the weekly On Demand scan client task. 

For the designated weekly On Demand scan client task, verify the "Task Type" is listed as "On Demand Scan".
Under the "Task Name" column, click on the link for the designated task to review the task properties.

In the "Where" tab, populate the "Specify where scanning will take place" field with all local drives.
Next to "Scan options", select the checkbox for "Include sub-directories".

Click Save.'
  impact 0.5
  ref 'DPMS Target McAfee VirusScan Enterprise for Linux (VSEL) 1.9'
  tag check_id: 'C-50143r3_chk'
  tag severity: 'medium'
  tag gid: 'V-49109'
  tag rid: 'SV-62011r1_rule'
  tag stig_id: 'DTAVSEL-113'
  tag gtitle: 'DTAVSEL-113-McAfee MOVE VSEL for SVA ODS scan local drives'
  tag fix_id: 'F-52399r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
