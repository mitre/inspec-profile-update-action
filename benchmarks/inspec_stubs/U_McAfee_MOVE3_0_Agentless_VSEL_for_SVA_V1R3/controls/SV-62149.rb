control 'SV-62149' do
  title 'The McAfee VirusScan Enterprise for Linux 1.9.0 On Demand scanner must be configured to decompress archives when scanning.'
  desc 'Malware is often packaged within an archive. In addition, archives might have other archives within. Not scanning archive files introduces the risk of infected files being introduced into the environment.'
  desc 'check', 'From the ePO server console System Tree, select "My Organization". Select the "Systems" tab. To show all systems in the System Tree, select "This Group and All Subgroups" from the "Preset:" drop-down list. From the list of systems, locate the asset representing the McAfee MOVE Security Virtual Appliance (SVA). Click on the system to open the System Information page. 

Click on Actions | Agent | Modify Tasks on a Single System.   

From the list of available tasks in the "Task Name" column, with the assistance of the ePO SA, identify the weekly On Demand scan client task. 

If a weekly On Demand scan client task does not exist, this is a finding.

For the designated weekly On Demand scan client task, verify the "Task Type" is listed as "On Demand Scan".
Verify the "Status" is listed as "Enabled".
Under the "Task Name" column, click on the link for the designated task to review the task properties.

In the "Advanced" tab, next to the Compressed files, verify the check box for "Scan inside multiple-file archives (e.g. .ZIP)" has been selected.

If the task designated as the regularly scheduled On Demand Scan, next to the Compressed files, the check box for "Scan inside multiple-file archives (e.g. .ZIP)" is not selected, this is a finding.'
  desc 'fix', 'From the ePO server console System Tree, select "My Organization". Select the "Systems" tab. To show all systems in the System Tree, select "This Group and All Subgroups" from the "Preset:" drop-down list. From the list of systems, locate the asset representing the McAfee MOVE Security Virtual Appliance (SVA). Click on the system to open the System Information page. 

If a task does not exist for the regularly scheduled weekly scan, create a New Client Task to run an On Demand scan at least weekly.

Click on Actions | Agent | Modify Tasks on a Single System.  

From the list of available tasks in the "Task Name" column, with the assistance of the ePO SA, identify the weekly On Demand scan client task. 
Under the "Task Name" column, click on the link for the designated task to review the task properties.

In the "Advanced" tab, next to the Compressed files, select the check box for "Scan inside multiple-file archives (e.g. .ZIP)".

Click Save.'
  impact 0.5
  ref 'DPMS Target McAfee VirusScan Enterprise for Linux (VSEL) 1.9'
  tag check_id: 'C-49443r3_chk'
  tag severity: 'medium'
  tag gid: 'V-49243'
  tag rid: 'SV-62149r1_rule'
  tag stig_id: 'DTAVSEL-101'
  tag gtitle: 'DTAVSEL-101-McAfee MOVE VSEL for SVA ODS decompress archive files'
  tag fix_id: 'F-49554r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
