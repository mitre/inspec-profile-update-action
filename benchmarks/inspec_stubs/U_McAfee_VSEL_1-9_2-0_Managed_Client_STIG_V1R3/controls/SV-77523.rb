control 'SV-77523' do
  title 'The McAfee VirusScan Enterprise for Linux 1.9.x/2.0.x must be configured to run a scheduled On-Demand scan at least once a week.'
  desc 'Anti-virus software is the most commonly used technical control for malware threat mitigation. Real-time scanning of files as they are read from disk is a crucial first line of defense from malware attacks but to ensure all files are frequently scanned, a regularly scheduled full scan will ensure malware missed by the real-time scanning will be detected and mitigated.'
  desc 'check', 'From the ePO server console System Tree, select "My Organization". 

Select the "Systems" tab. To show all systems in the System Tree, select "This Group and All Subgroups" from the "Preset:" drop-down list.

From the list of systems, locate the asset representing the Linux system being reviewed. 

Click on the system to open the System Information page.
Click on Actions >> Agent >> Modify Tasks on a Single System.

From the list of available tasks in the "Task Name" column, with the assistance of the ePO SA, identify the weekly On Demand scan client task. 

If a weekly On Demand scan client task does not exist, this is a finding.

For the designated weekly On Demand scan client task, verify the "Task Type" is listed as "On Demand Scan".

Verify the "Status" is listed as "Enabled".

If the task designated as the weekly On Demand scan client task’s "Status" is not listed as "Enabled", this is a finding.'
  desc 'fix', 'From the ePO server console System Tree, select "My Organization".

Select the "Systems" tab. To show all systems in the System Tree, select "This Group and All Subgroups" from the "Preset:" drop-down list.

From the list of systems, locate the asset representing the Linux system being reviewed.

Click on the system to open the System Information page.

Create a New Client Task to run a regularly schedule On Demand scan at least weekly, with the following selected:

In the "Advanced" tab, next to the Heuristics, select the check box for "Find unknown program viruses".
In the "Advanced" tab, next to the Compressed files, select the check box for "Scan inside multiple-file archives (e.g. .ZIP)".
In the "Advanced" tab, next to "Heuristics:", select the check box for "Find unknown macro viruses".
In the "Advanced" tab, next to "Non-viruses:", select the check box for "Find potentially unwanted programs". 
In the "Advanced" tab, select the check box for "Disable client Web UI:".
In the "Advanced" tab, next to the Compressed files, select the check box for "Decode MIME encoded files:".

In the "Where" tab, select the "Specify where scanning will take place" field is populated with all local drives.

In the "Detection" tab, next to "What to scan:", select the radio button for "All files".

In the "Actions" tab, next to "When Viruses and Trojans are found:", select the radio button for "Clean infected files automatically".
In the "Actions" tab, next to "When Programs & Jokes are found:", select the radio button for "Clean infected files automatically".
In the "Actions" tab, next to "When Programs & Jokes are found: If the above action fails:", select the radio button for "Move infected files to the quarantine directory".

Click "Save".'
  impact 0.5
  ref 'DPMS Target McAfee VSEL Managed Client'
  tag check_id: 'C-63785r3_chk'
  tag severity: 'medium'
  tag gid: 'V-63033'
  tag rid: 'SV-77523r2_rule'
  tag stig_id: 'DTAVSEL-100'
  tag gtitle: 'SRG-APP-000277'
  tag fix_id: 'F-68951r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001241']
  tag nist: ['SI-3 c 1']
end
