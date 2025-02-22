control 'SV-77619' do
  title 'The McAfee VirusScan Enterprise for Linux 1.9.x/2.0.x On-Demand scanner must be configured to Move infected files to the quarantine directory if first action fails when programs and jokes are found.'
  desc 'Potentially Unwanted Programs (PUPs) include Spyware, Adware, Remote Administration Tools, Dialers, Password Crackers, Jokes, and Key Loggers. While PUPs do not typically have any infection capability on their own, they rely on malware or other attach mechanisms to be installed onto target hosts, after which they will collect and transfer data from the host to an external host and/or will be used as attach mechanisms. Configuring the anti-virus software to attempt to clean the file first will allow for the possibility of a false positive. In most cases, however, the secondary action of delete will be used, mitigating the risk of the PUPs being installed and used maliciously.'
  desc 'check', %q(From a desktop browser window, connect to the McAfee VirusScan Enterprise for Linux (VSEL) Monitor (WEB interface) of the Linux system being reviewed and logon with the nails user account.

In the VSEL WEB Monitor, review tasks under "View", "Scheduled Tasks".
With the System Administrator's assistance, determine which task is intended as the regularly scheduled scan task.
Click on the task, and then click "Modify".
Under "2. What to Scan", click "Next".
Under "3. Choose Scan Settings", "Anti-virus Actions", verify "Quarantine" is selected in the second dropdown list "Actions for Programs and Jokes" if first action fails.

If "Quarantine" is not selected in the second dropdown list "Actions for Programs and Jokes" if first action fails, this is a finding.

To validate without the Web interface, access the Linux system being reviewed, either at the console or by a SSH connection.
At the command line, navigate to /var/opt/NAI/LinuxShield/etc.
Enter the command "grep "ODS.action.Default.secondary" ods.cfg"

If the response given for "ODS.action.Default.secondary" is not "Quarantine", this is a finding.)
  desc 'fix', %q(From a desktop browser window, connect to the McAfee VirusScan Enterprise for Linux (VSEL) Monitor (WEB interface) of the Linux system being reviewed and logon with the nails user account.

In the VSEL WEB Monitor, review tasks under "View", "Scheduled Tasks".
With the System Administrator's assistance, determine which task is intended as the regularly scheduled scan task.
Click on the task, and then click "Modify".
Under "2. What to Scan", click "Next".
Under "3. Choose Scan Settings", Anti-virus Actions", select "Quarantine" from the second dropdown list "Actions for Programs and Jokes" if first action fails, click "Next", and then click "Finish".)
  impact 0.5
  ref 'DPMS Target McAfee VSEL Local Client'
  tag check_id: 'C-63881r1_chk'
  tag severity: 'medium'
  tag gid: 'V-63129'
  tag rid: 'SV-77619r1_rule'
  tag stig_id: 'DTAVSEL-111'
  tag gtitle: 'SRG-APP-000277'
  tag fix_id: 'F-69047r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001241']
  tag nist: ['SI-3 c 1']
end
