control 'SV-61991' do
  title 'Any paths and files excluded by the McAfee VirusScan Enterprise for Linux 1.9.0 On Demand scanner must be documented with, and approved by, the IAO/IAM.'
  desc 'When scanning for malware, excluding specific files will increase the risk of a malware-infected file going undetected. By configuring antivirus software without any exclusions, the scanner has a higher success rate at detecting and eradicating malware.'
  desc 'check', 'From the ePO server console System Tree, select "My Organization". Select the "Systems" tab. To show all systems in the System Tree, select "This Group and All Subgroups" from the "Preset:" drop-down list. From the list of systems, locate the asset representing the McAfee MOVE Security Virtual Appliance (SVA). Click on the system to open the System Information page. 

Click on Actions | Agent | Modify Tasks on a Single System.  

From the list of available tasks in the "Task Name" column, with the assistance of the ePO SA, identify the weekly On Demand scan client task. 

If a weekly On Demand scan client task does not exist, this is a finding.

For the designated weekly On Demand scan client task, verify the "Task Type" is listed as "On Demand Scan".
Verify the "Status" is listed as "Enabled".
Under the "Task Name" column, click on the link for the designated task to review the task properties.

In the "Detection" tab, next to "What not to scan:", verify no entries exist.
If any entries exist, verify the exclusion of those files and directories has been documented by the System Administrator and approved by the IAO/IAM.

If any entries are present in the "What not to scan:" setting for the "Select files and directories to be excluded from virus scanning" field, and those files and directories have not been documented by the System Administrator and approved by the IAO/IAM, this is a finding.

If any entries are present in the "What not to scan:" setting for the "Select files and directories to be excluded from virus scanning" field, and those files and directories have been documented by the System Administrator and approved by the IAO/IAM, this is not a finding.'
  desc 'fix', 'From the ePO server console System Tree, select "My Organization". Select the "Systems" tab. To show all systems in the System Tree, select "This Group and All Subgroups" from the "Preset:" drop-down list. From the list of systems, locate the asset representing the McAfee MOVE Security Virtual Appliance (SVA). Click on the system to open the System Information page. 

If a task does not exist for the regularly scheduled weekly scan, create a New Client Task to run an On Demand scan at least weekly.

Click on Actions | Agent | Modify Tasks on a Single System.  

From the list of available tasks in the "Task Name" column, with the assistance of the ePO SA, identify the weekly On Demand scan client task. 

For the designated weekly On Demand scan client task, verify the "Task Type" is listed as "On Demand Scan".
Under the "Task Name" column, click on the link for the designated task to review the task properties.

In the "Detection" tab, next to "What not to scan:", remove any entries from the "What not to scan:" section for which there has not been IAO/IAM approval.

Click Save.'
  impact 0.5
  ref 'DPMS Target McAfee VirusScan Enterprise for Linux (VSEL) 1.9'
  tag check_id: 'C-49450r2_chk'
  tag severity: 'medium'
  tag gid: 'V-49089'
  tag rid: 'SV-61991r1_rule'
  tag stig_id: 'DTAVSEL-108'
  tag gtitle: 'DTAVSEL-108-McAfee MOVE VSEL for SVA ODS file exclusions'
  tag fix_id: 'F-49561r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
