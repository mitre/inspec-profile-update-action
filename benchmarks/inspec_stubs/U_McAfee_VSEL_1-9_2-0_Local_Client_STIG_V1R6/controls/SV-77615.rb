control 'SV-77615' do
  title 'The McAfee VirusScan Enterprise for Linux 1.9.x/2.0.x On-Demand scanner must only be configured with exclusions that are documented and approved by the ISSO/ISSM/AO.'
  desc 'When scanning for malware, excluding specific files will increase the risk of a malware-infected file going undetected. By configuring anti-virus software without any exclusions, the scanner has a higher success rate at detecting and eradicating malware.'
  desc 'check', %q(From a desktop browser window, connect to the McAfee VirusScan Enterprise for Linux (VSEL) Monitor (WEB interface) of the Linux system being reviewed and logon with the nails user account.

In the VSEL WEB Monitor, review tasks under "View", "Scheduled Tasks".
With the System Administrator's assistance, determine which task is intended as the regularly scheduled scan task.
Click on the task, and then click "Modify".
Under "2. What to Scan", click "Next".
Under "3. Choose Scan Settings", "Paths Excluded From Scanning".

If any paths other than the following paths are excluded, and the exclusions have not been documented and approved by the ISSO/ISSM/AO, this is a finding.

/var/log
/_admin/Manage_NSS
/mnt/system/log
/media/nss/.*/(\._NETWARE|\._ADMIN)
/.*\.(vmdk|VMDK|dbl|DBL|ctl|CTL|log|LOG|jar|JAR|war|WAR|dtx|DTX|dbf|DBF|frm|FRM|myd|MYD|myi|MYI|rdo|RDO|arc|ARC)
/cgroup
/dev
/proc
/selinux
/sys)
  desc 'fix', %q(From a desktop browser window, connect to the McAfee VirusScan Enterprise for Linux (VSEL) Monitor (WEB interface) of the Linux system being reviewed and logon with the nails user account.

In the VSEL WEB Monitor, review tasks under "View", "Scheduled Tasks".
With the System Administrator's assistance, determine which task is intended as the regularly scheduled scan task.
Click on the task, and then click "Modify".
Under "2. What to Scan", click "Next".
Under "3. Choose Scan Settings", "Paths Excluded From Scanning", removed all unauthorized excluded paths, click "Next, and then click "Finish".)
  impact 0.5
  ref 'DPMS Target McAfee VSEL Local Client'
  tag check_id: 'C-63877r1_chk'
  tag severity: 'medium'
  tag gid: 'V-63125'
  tag rid: 'SV-77615r1_rule'
  tag stig_id: 'DTAVSEL-108'
  tag gtitle: 'SRG-APP-000277'
  tag fix_id: 'F-69043r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001241']
  tag nist: ['SI-3 c 1']
end
