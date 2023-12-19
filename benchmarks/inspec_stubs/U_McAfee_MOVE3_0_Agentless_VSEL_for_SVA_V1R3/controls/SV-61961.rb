control 'SV-61961' do
  title 'The McAfee VirusScan Enterprise for Linux 1.9.0 must be configured to run a scheduled On Demand scan at least once a week.'
  desc 'Antivirus software is the most commonly used technical control for malware threat mitigation. Real-time scanning of files as they are read from disk is a crucial first line of defense from malware attacks but to ensure all files are frequently scanned, a regularly scheduled full scan will ensure malware missed by the real-time scanning will be detected and mitigated.'
  desc 'check', 'From the ePO server console System Tree, select "My Organization". Select the "Systems" tab. To show all systems in the System Tree, select "This Group and All Subgroups" from the "Preset:" drop-down list. From the list of systems, locate the asset representing the McAfee MOVE Security Virtual Appliance (SVA). Click on the system to open the System Information page. 

Click on Actions | Agent | Modify Tasks on a Single System.   

From the list of available tasks in the "Task Name" column, with the assistance of the ePO SA, identify the weekly On Demand scan client task. 

If a weekly On Demand scan client task does not exist, this is a finding.

For the designated weekly On Demand scan client task, verify the "Task Type" is listed as "On Demand Scan".
Verify the "Status" is listed as "Enabled".
Under the "Task Name" column, click on the link for the designated task to review the task properties.
Verify the task is scheduled to run at least weekly.
If the task is not scheduled to run at least weekly, this is a finding.'
  desc 'fix', 'From the ePO server console System Tree, select "My Organization". Select the "Systems" tab. To show all systems in the System Tree, select "This Group and All Subgroups" from the "Preset:" drop-down list. From the list of systems, locate the asset representing the McAfee MOVE Security Virtual Appliance (SVA). Click on the system to open the System Information page. 

Create a New Client Task to run a regularly schedule On Demand scan at least weekly.

Click Save.'
  impact 0.5
  ref 'DPMS Target McAfee VirusScan Enterprise for Linux (VSEL) 1.9'
  tag check_id: 'C-50135r3_chk'
  tag severity: 'medium'
  tag gid: 'V-49059'
  tag rid: 'SV-61961r1_rule'
  tag stig_id: 'DTAVSEL-100'
  tag gtitle: 'DTAVSEL-100-McAfee VSEL for SVA ODS scheduled scan frequency'
  tag fix_id: 'F-52391r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
