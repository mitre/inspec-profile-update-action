control 'SV-77583' do
  title 'The McAfee VirusScan Enterprise for Linux 1.9.x/2.0.x On-Access scanner must only be configured with exclusions that are documented and approved by the ISSO/ISSM/AO.'
  desc 'When scanning for malware, excluding specific files will increase the risk of a malware-infected file going undetected. By configuring anti-virus software without any exclusions, the scanner has a higher success rate at detecting and eradicating malware.'
  desc 'check', 'From a desktop browser window, connect to the McAfee VirusScan Enterprise for Linux (VSEL) Monitor (WEB interface) of the Linux system being reviewed and logon with the nails user account.

In the VSEL WEB Monitor, under "Configure", select "On-Access Settings".

Under "Paths Excluded From Scanning", verify no entries exist other than the following:
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

If any entries other than the above referenced paths are present in the "Paths Excluded From Scanning" field, verify the exclusion of those files and paths have been formally documented by the System Administrator and has been approved by the ISSO/ISSM.

If they have not been formally documented by the System Administrator and approved by the ISSO/ISSM, this is a finding.

If they have not been formally documented by the System Administrator and approved by the ISSO/ISSM but are validated as being scanned within the regularly scheduled scan, this is a finding but can be dropped to a CAT 3.

To validate without the Web interface, access the Linux system being reviewed, either at the console or by a SSH connection.
At the command line, navigate to /var/opt/NAI/LinuxShield/etc.
Enter the command "grep "exclude-path" nailsd.cfg -A 5"

If the response given is: "nailsd.profile.OAS.filter.varlog.type: exclude-path" and "nailsd.profile.OAS.filter.varlog.path:" includes anything other than the above paths", this is a finding.'
  desc 'fix', 'From a desktop browser window, connect to the McAfee VirusScan Enterprise for Linux (VSEL) Monitor (WEB interface) of the Linux system being reviewed and logon with the nails user account.

In the VSEL WEB Monitor, under "Configure", select "On-Access Settings".
Click "Edit".
Under "Paths Excluded From Scanning", remove all entries other than the default "/var/log".

Click "Apply".'
  impact 0.5
  ref 'DPMS Target McAfee VSEL Local Client'
  tag check_id: 'C-63845r1_chk'
  tag severity: 'medium'
  tag gid: 'V-63093'
  tag rid: 'SV-77583r1_rule'
  tag stig_id: 'DTAVSEL-012'
  tag gtitle: 'SRG-APP-000279'
  tag fix_id: 'F-69011r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001243']
  tag nist: ['SI-3 c 2']
end
