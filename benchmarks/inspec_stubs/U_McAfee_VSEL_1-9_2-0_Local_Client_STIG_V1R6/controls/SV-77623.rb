control 'SV-77623' do
  title 'The McAfee VirusScan Enterprise for Linux 1.9.x/2.0.x On-Demand scanner must be configured to include all local drives and their sub-directories.'
  desc 'When scanning for malware, excluding specific file types will increase the risk of a malware-infected file going undetected. By configuring anti-virus software to scan all file types, the scanner has a higher success rate at detecting and eradicating malware.'
  desc 'check', %q(From a desktop browser window, connect to the McAfee VirusScan Enterprise for Linux (VSEL) Monitor (WEB interface) of the Linux system being reviewed and logon with the nails user account.

In the VSEL WEB Monitor, review tasks under "View", "Scheduled Tasks".
With the System Administrator's assistance, determine which task is intended as the regularly scheduled scan task.

Click on the task, and then click "Modify".
Under "3. Choose Scan Settings", verify “Scan all files” check box is selected.

If the Scan Settings are not configured to Scan all files, this is a finding.

To validate without the Web interface, access the Linux system being reviewed, either at the console or by a SSH connection.
At the command line, navigate to /var/opt/NAI/LinuxShield/etc.
Enter the command "grep "cat /var/opt/NAI.LinuxShield/etc/ods.cfg | grep extension.mode"

If the response given is not "All", this is a finding.)
  desc 'fix', %q(From a desktop browser window, connect to the McAfee VirusScan Enterprise for Linux (VSEL) Monitor (WEB interface) of the Linux system being reviewed and logon with the nails user account.

In the VSEL WEB Monitor, review tasks under "View", "Scheduled Tasks".
With the System Administrator's assistance, determine which task is intended as the regularly scheduled scan task.
Click on the task, and then click "Modify".
Under "3. Choose Scan Settings", select the “Scan all files” check box.)
  impact 0.5
  ref 'DPMS Target McAfee VSEL Local Client'
  tag check_id: 'C-63885r2_chk'
  tag severity: 'medium'
  tag gid: 'V-63133'
  tag rid: 'SV-77623r2_rule'
  tag stig_id: 'DTAVSEL-113'
  tag gtitle: 'SRG-APP-000277'
  tag fix_id: 'F-69051r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001241']
  tag nist: ['SI-3 c 1']
end
