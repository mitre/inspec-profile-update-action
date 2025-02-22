control 'SV-77539' do
  title 'The McAfee VirusScan Enterprise for Linux 1.9.x/2.0.x On-Demand scanner must only be configured with exclusions which are documented and approved by the ISSO/ISSM/AO.'
  desc 'When scanning for malware, excluding specific files will increase the risk of a malware-infected file going undetected. By configuring anti-virus software without any exclusions, the scanner has a higher success rate at detecting and eradicating malware.'
  desc 'check', 'From the ePO server console System Tree, select "My Organization". Select the "Systems" tab. To show all systems in the System Tree, select "This Group and All Subgroups" from the "Preset:" drop-down list.

From the list of systems, locate the asset representing the Linux system being reviewed. Click on the system to open the System Information page. 

Click on Actions >> Agent >> Modify Tasks on a Single System.

From the list of available tasks in the "Task Name" column, with the assistance of the ePO SA, identify the weekly On Demand scan client task.

If a weekly On Demand scan client task does not exist, this is a finding.

For the designated weekly On Demand scan client task, verify the "Task Type" is listed as "On Demand Scan".
Verify the "Status" is listed as "Enabled".
Under the "Task Name" column, click on the link for the designated task to review the task properties.
In the "Detection" tab, next to "What not to scan:", verify no entries exist other than the following approved paths:

/var/log
/_admin/Manage_NSS
/mnt/system/log
/media/nss/.*/(\\._NETWARE|\\._ADMIN)
/.*\\.(vmdk|VMDK|dbl|DBL|ctl|CTL|log|LOG|jar|JAR|war|WAR|dtx|DTX|dbf|DBF|frm|
FRM|myd|MYD|myi|MYI|rdo|RDO|arc|ARC)
/cgroup
/dev
/proc
/selinux
/sys
/quarantine (or other custom configured quarantine directory)

If any entries exist, verify the exclusion of those files and directories has been documented by the System Administrator and approved by the
ISSO/ISSM.'
  desc 'fix', 'From the ePO server console System Tree, select "My Organization". Select the "Systems" tab. To show all systems in the System Tree, select "This Group and All Subgroups" from the "Preset:" drop-down list.

From the list of systems, locate the asset representing the Linux system being reviewed. Click on the system to open the System Information page.

If a task does not exist for the regularly scheduled weekly scan, create a New Client Task to run an On Demand scan at least weekly.

Click on Actions >> Agent >> Modify Tasks on a Single System.

From the list of available tasks in the "Task Name" column, with the assistance of the ePO SA, identify the weekly On Demand scan client task. 

For the designated weekly On Demand scan client task, verify the "Task Type" is listed as "On Demand Scan".
Under the "Task Name" column, click on the link for the designated task to review the task properties.
In the "Detection" tab, next to "What not to scan:", remove any entries from the "What not to scan:" section for which there has not been ISSO/ISSM approval.

Click "Save".'
  impact 0.5
  ref 'DPMS Target McAfee VSEL Managed Client'
  tag check_id: 'C-63801r2_chk'
  tag severity: 'medium'
  tag gid: 'V-63049'
  tag rid: 'SV-77539r2_rule'
  tag stig_id: 'DTAVSEL-108'
  tag gtitle: 'SRG-APP-000277'
  tag fix_id: 'F-68967r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001241']
  tag nist: ['SI-3 c 1']
end
