control 'SV-77611' do
  title 'The McAfee VirusScan Enterprise for Linux 1.9.x/2.0.x On-Demand scanner must be configured to Clean infected files automatically as first action when a virus or Trojan is detected.'
  desc 'Malware may have infected a file that is necessary to the user. By configuring the anti-virus software to first attempt cleaning the infected file, availability to the file is not sacrificed. If a cleaning attempt is not successful, however, deleting the file is the only safe option to ensure the malware is not introduced onto the system or network.'
  desc 'check', %q(From a desktop browser window, connect to the McAfee VirusScan Enterprise for Linux (VSEL) Monitor (WEB interface) of the Linux system being reviewed and logon with the nails user account.

In the VSEL WEB Monitor, review tasks under "View", "Scheduled Tasks".
With the System Administrator's assistance, determine which task is intended as the regularly scheduled scan task.
Click on the task, and then click "Modify".
Under "2. What to Scan", click "Next".
Under "3. Choose Scan Settings", "Anti-virus Actions", verify "Clean" is selected in the first dropdown list for "Actions for Viruses and Trojans".

If "Clean" is not selected in the first dropdown list for "Actions for Viruses and Trojans", this is a finding.

To validate without the Web interface, access the Linux system being reviewed, either at the console or by a SSH connection.
At the command line, navigate to /var/opt/NAI/LinuxShield/etc.
Enter the command "grep "ODS.action.App.primary" ods.cfg"

If the response given for "nailsd.profile.ODS.action.App.primary" is not "Clean", this is a finding.)
  desc 'fix', %q(From a desktop browser window, connect to the McAfee VirusScan Enterprise for Linux (VSEL) Monitor (WEB interface) of the Linux system being reviewed and logon with the nails user account.

In the VSEL WEB Monitor, review tasks under "View", "Scheduled Tasks".
With the System Administrator's assistance, determine which task is intended as the regularly scheduled scan task.
Click on the task, and then click "Modify".
Under "2. What to Scan", click "Next".
Under "3. Choose Scan Settings", Anti-virus Actions", select "Clean" from the first dropdown list for "Actions for Viruses and Trojans", click "Next", and then click "Finish".)
  impact 0.5
  ref 'DPMS Target McAfee VSEL Local Client'
  tag check_id: 'C-63873r1_chk'
  tag severity: 'medium'
  tag gid: 'V-63121'
  tag rid: 'SV-77611r1_rule'
  tag stig_id: 'DTAVSEL-106'
  tag gtitle: 'SRG-APP-000277'
  tag fix_id: 'F-69039r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001241']
  tag nist: ['SI-3 c 1']
end
