control 'SV-61985' do
  title 'The McAfee VirusScan Enterprise for Linux 1.9.0 On Demand scanner must be configured to Move infected files to the quarantine directory if first action fails for when Viruses and Trojans are found.'
  desc 'Malware may have infected a file that is necessary to the user. By configuring the antivirus software to first attempt cleaning the infected file, availability to the file is not sacrificed. If a cleaning attempt is not successful, however, deleting the file is the only safe option to ensure the malware is not introduced onto the system or network.'
  desc 'check', 'From the ePO server console System Tree, select "My Organization". Select the "Systems" tab. To show all systems in the System Tree, select "This Group and All Subgroups" from the "Preset:" drop-down list. From the list of systems, locate the asset representing the McAfee MOVE Security Virtual Appliance (SVA). Click on the system to open the System Information page. 

Click on Actions | Agent | Modify Tasks on a Single System.  

From the list of available tasks in the "Task Name" column, with the assistance of the ePO SA, identify the weekly On Demand scan client task. 

If a weekly On Demand scan client task does not exist, this is a finding.

For the designated weekly On Demand scan client task, verify the "Task Type" is listed as "On Demand Scan".
Verify the "Status" is listed as "Enabled".
Under the "Task Name" column, click on the link for the designated task to review the task properties.

In the "Actions" tab, next to "If the above action fails:", verify the radio button for "Move infected files to the quarantine directory" is selected.
Verify the "Quarantine Directory:" field is populated with "/quarantine" (or another valid location as determined by the organization).

If the radio button for "If the above action fails: Move infected files to the quarantine directory" is not selected, this is a finding.
If the "Quarantine Directory:" field is not populated, this is a finding.'
  desc 'fix', 'From the ePO server console System Tree, select "My Organization". Select the "Systems" tab. To show all systems in the System Tree, select "This Group and All Subgroups" from the "Preset:" drop-down list. From the list of systems, locate the asset representing the McAfee MOVE Security Virtual Appliance (SVA). Click on the system to open the System Information page. 

If a task does not exist for the regularly scheduled weekly scan, create a New Client Task to run an On Demand scan at least weekly.

Click on Actions | Agent | Modify Tasks on a Single System.  

From the list of available tasks in the "Task Name" column, with the assistance of the ePO SA, identify the weekly On Demand scan client task. 

For the designated weekly On Demand scan client task, verify the "Task Type" is listed as "On Demand Scan".
Under the "Task Name" column, click on the link for the designated task to review the task properties.

In the "Actions" tab, next to "If the above action fails:", select the radio button for "Move infected files to the quarantine directory".
Populate the "Quarantine Directory:" field with "/quarantine" (or another valid location as determined by the organization).

Click Save.'
  impact 0.5
  ref 'DPMS Target McAfee VirusScan Enterprise for Linux (VSEL) 1.9'
  tag check_id: 'C-49449r2_chk'
  tag severity: 'medium'
  tag gid: 'V-49083'
  tag rid: 'SV-61985r1_rule'
  tag stig_id: 'DTAVSEL-107'
  tag gtitle: 'DTAVSEL-107-McAfee MOVE VSEL for SVA ODS scan second action'
  tag fix_id: 'F-49560r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
