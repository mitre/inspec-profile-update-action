control 'SV-77601' do
  title 'The McAfee VirusScan Enterprise for Linux 1.9.x/2.0.x On-Demand scanner must be configured to decompress archives when scanning.'
  desc 'Malware is often packaged within an archive. In addition, archives might have other archives within. Not scanning archive files introduces the risk of infected files being introduced into the environment.'
  desc 'check', %q(From a desktop browser window, connect to the McAfee VirusScan Enterprise for Linux (VSEL) Monitor (WEB interface) of the Linux system being reviewed and logon with the nails user account.

In the VSEL WEB Monitor, review tasks under "View", "Scheduled Tasks".
With the System Administrator's assistance, determine which task is intended as the regularly scheduled scan task.
Click on the task, and then click "Modify".
Under "2. What to Scan", click "Next".
Under "3. Choose Scan Settings", "Anti-virus Scanning Options", verify the "Decompress archives" check box has been selected.

If the "Decompress archives" check box has not been selected, this is a finding.

To validate without the Web interface, access the Linux system being reviewed, either at the console or by a SSH connection.
At the command line, navigate to /var/opt/NAI/LinuxShield/etc.
Enter the command "grep "ODS.decompArchive" ods.cfg"

If the response given for "nailsd.profile.ODS.decompArchive" is not "true", this is a finding.)
  desc 'fix', %q(From a desktop browser window, connect to the McAfee VirusScan Enterprise for Linux (VSEL) Monitor (WEB interface) of the Linux system being reviewed and logon with the nails user account.

In the VSEL WEB Monitor, review tasks under "View", "Scheduled Tasks".
With the System Administrator's assistance, determine which task is intended as the regularly scheduled scan task.
Click on the task, and then click "Modify".
Under "2. What to Scan", click "Next".
Under "3. Choose Scan Settings", "Anti-virus Scanning Options", select the "Decompress archives" check box, click "Next", and then click "Finish".)
  impact 0.5
  ref 'DPMS Target McAfee VSEL Local Client'
  tag check_id: 'C-63863r1_chk'
  tag severity: 'medium'
  tag gid: 'V-63111'
  tag rid: 'SV-77601r1_rule'
  tag stig_id: 'DTAVSEL-101'
  tag gtitle: 'SRG-APP-000277'
  tag fix_id: 'F-69029r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001241']
  tag nist: ['SI-3 c 1']
end
