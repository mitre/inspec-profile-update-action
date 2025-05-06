control 'SV-77535' do
  title 'The McAfee VirusScan Enterprise for Linux 1.9.x/2.0.x On-Demand scanner must be configured to Clean infected files automatically as first action when a virus or Trojan is detected.'
  desc 'Malware may have infected a file that is necessary to the user. By configuring the anti-virus software to first attempt cleaning the infected file, availability to the file is not sacrificed. If a cleaning attempt is not successful, however, deleting the file is the only safe option to ensure the malware is not introduced onto the system or network.'
  desc 'check', 'From the ePO server console System Tree, select "My Organization". Select the "Systems" tab. To show all systems in the System Tree, select "This Group and All Subgroups" from the "Preset:" drop-down list.

From the list of systems, locate the asset representing the Linux system being reviewed. Click on the system to open the System Information page. 

Click on Actions >> Agent >> Modify Tasks on a Single System.

From the list of available tasks in the "Task Name" column, with the assistance of the ePO SA, identify the weekly On Demand scan client task.

If a weekly On Demand scan client task does not exist, this is a finding.

For the designated weekly On Demand scan client task, verify the "Task Type" is listed as "On Demand Scan".
Verify the "Status" is listed as "Enabled".
Under the "Task Name" column, click on the link for the designated task to review the task properties.
In the "Actions" tab, next to "When Viruses and Trojans are found:", verify the radio button for "Clean infected files automatically" is selected.

If the radio button for "When Viruses and Trojans are found: Clean infected files automatically" is not selected, this is a finding.'
  desc 'fix', 'From the ePO server console System Tree, select "My Organization". Select the "Systems" tab. To show all systems in the System Tree, select "This Group and All Subgroups" from the "Preset:" drop-down list.

From the list of systems, locate the asset representing the Linux system being reviewed. Click on the system to open the System Information page. 

If a task does not exist for the regularly scheduled weekly scan, create a New Client Task to run an On Demand scan at least weekly.

Click on Actions >> Agent >> Modify Tasks on a Single System.

From the list of available tasks in the "Task Name" column, with the assistance of the ePO SA, identify the weekly On Demand scan client task.

For the designated weekly On Demand scan client task, verify the "Task Type" is listed as "On Demand Scan".
Under the "Task Name" column, click on the link for the designated task to review the task properties.
In the "Actions" tab, next to "When Viruses and Trojans are found:", select the radio button for "Clean infected files automatically".

Click "Save".'
  impact 0.5
  ref 'DPMS Target McAfee VSEL Managed Client'
  tag check_id: 'C-63797r1_chk'
  tag severity: 'medium'
  tag gid: 'V-63045'
  tag rid: 'SV-77535r1_rule'
  tag stig_id: 'DTAVSEL-106'
  tag gtitle: 'SRG-APP-000277'
  tag fix_id: 'F-68963r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001241']
  tag nist: ['SI-3 c 1']
end
