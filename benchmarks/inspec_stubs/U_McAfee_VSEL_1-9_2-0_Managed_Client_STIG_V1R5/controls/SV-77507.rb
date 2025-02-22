control 'SV-77507' do
  title 'The McAfee VirusScan Enterprise for Linux 1.9.x/2.0.x On-Access scanner must only be configured with exclusions which are documented and approved by the ISSO/ISSM/AO.'
  desc 'When scanning for malware, excluding specific files will increase the risk of a malware-infected file going undetected. By configuring anti-virus software without any exclusions, the scanner has a higher success rate at detecting and eradicating malware.'
  desc 'check', 'From the ePO server console System Tree, select "My Organization". Select the "Systems" tab. To show all systems in the System Tree, select "This Group and All Subgroups" from the "Preset:" drop-down list. 

From the list of systems, locate the asset representing the Linux system being reviewed. Click on the system to open the System Information page. 

Click on Actions >> Agent >> Modify Policies on a Single System. 

From the "Product:" drop-down list, select "VirusScan Enterprise for Linux 1.9.x/2.0.x".

From the "Policy" column, click on the policy for the "On-Access Scanning Policy".

In the "Detections" tab, next to "What not to scan:", verify the only entries for the "Select files and directories to be excluded from virus scanning" field are those below:

Under "Paths Excluded From Scanning", verify no entries exist other than the allowed default paths referenced below:

/var/log
/_admin/Manage_NSS
/mnt/system/log
/media/nss/.*/(\\._NETWARE|\\._ADMIN)
/.*\\.(vmdk|VMDK|dbl|DBL|ctl|CTL|log|LOG|jar|JAR|war|WAR|dtx|DTX|dbf|DBF|frm|FRM|myd|MYD|myi|MYI|rdo|RDO|arc|ARC)
/cgroup
/dev
/proc
/selinux
/sys

If any entries other than the default paths referenced above are present in the "What not to scan:" setting for the "Select files and directories to be excluded from virus scanning" field, verify the exclusion of those files and directories has been formally documented by the System Administrator and has been approved by the ISSO/ISSM.

If any entries other than the default paths referenced above are present in the "What not to scan:" setting for the "Select files and directories to be excluded from virus scanning" field, and those files and directories have not been formally documented by the System Administrator and approved by the ISSO/ISSM, this is a finding.

If any entries other than the default paths referenced above are present in the "What not to scan:" setting for the "Select files and directories to be excluded from virus scanning" field, and those files and directories have been formally documented by the System Administrator and approved by the ISSO/ISSM, this is not a finding.'
  desc 'fix', 'From the ePO server console System Tree, select "My Organization". Select the "Systems" tab. To show all systems in the System Tree, select "This Group and All Subgroups" from the "Preset:" drop-down list. 

From the list of systems, locate the asset representing the Linux system being reviewed. Click on the system to open the System Information page. 

Click on Actions >> Agent >> Modify Policies on a Single System. 

From the "Product:" drop-down list, select "VirusScan Enterprise for Linux 1.9.x/2.0.x".

From the "Policy" column, click on the policy for the "On-Access Scanning Policy".

In the "Detections" tab, next to "What not to scan:", verify the only entries for the "Select files and directories to be excluded from virus scanning" field are those below:

Under "Paths Excluded From Scanning", remove all entries other than the below listed of approved exclusions.  Any additional required exclusions must be documented by the System Administrator and approved by the ISSO/ISSM.

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
/sys'
  impact 0.5
  ref 'DPMS Target McAfee VSEL Managed Client'
  tag check_id: 'C-63769r2_chk'
  tag severity: 'medium'
  tag gid: 'V-63017'
  tag rid: 'SV-77507r2_rule'
  tag stig_id: 'DTAVSEL-012'
  tag gtitle: 'SRG-APP-000279'
  tag fix_id: 'F-68935r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001243']
  tag nist: ['SI-3 c 2']
end
