control 'SV-77605' do
  title 'The McAfee VirusScan Enterprise for Linux 1.9.x/2.0.x On-Demand scanner must be configured to find unknown macro viruses.'
  desc "Interpreted viruses are executed by an application. Within this subcategory, macro viruses take advantage of the capabilities of applications' macro programming language to infect application documents and document templates, while scripting viruses infect scripts that are understood by scripting languages processed by services on the OS. Many attackers use toolkits containing several different types of utilities and scripts that can be used to probe and attack hosts. Scanning for unknown macro viruses will mitigate zero-day attacks."
  desc 'check', %q(From a desktop browser window, connect to the McAfee VirusScan Enterprise for Linux (VSEL) Monitor (WEB interface) of the Linux system being reviewed and logon with the nails user account.

In the VSEL WEB Monitor, review tasks under "View", "Scheduled Tasks".
With the System Administrator's assistance, determine which task is intended as the regularly scheduled scan task.
Click on the task, and then click "Modify".
Under "2. What to Scan", click "Next".
Under "3. Choose Scan Settings", "Anti-virus Scanning Options", verify the "Perform macro analysis" check box has been selected.

If the "Perform macro analysis" check box has not been selected, this is a finding.

To validate without the Web interface, access the Linux system being reviewed, either at the console or by a SSH connection.
At the command line, navigate to /var/opt/NAI/LinuxShield/etc.
Enter the command "grep "ODS.macroAnalysis" ods.cfg"

If the response given for "nailsd.profile.ODS.macroAnalysis" is not "true", this is a finding.)
  desc 'fix', %q(From a desktop browser window, connect to the McAfee VirusScan Enterprise for Linux (VSEL) Monitor (WEB interface) of the Linux system being reviewed and logon with the nails user account.

In the VSEL WEB Monitor, review tasks under "View", "Scheduled Tasks".
With the System Administrator's assistance, determine which task is intended as the regularly scheduled scan task.
Click on the task, and then click "Modify".
Under "2. What to Scan", click "Next".
Under "3. Choose Scan Settings", "Anti-virus Scanning Options", select the "Perform macro analysis" check box, click "Next", and then click "Finish".)
  impact 0.5
  ref 'DPMS Target McAfee VSEL Local Client'
  tag check_id: 'C-63867r1_chk'
  tag severity: 'medium'
  tag gid: 'V-63115'
  tag rid: 'SV-77605r1_rule'
  tag stig_id: 'DTAVSEL-103'
  tag gtitle: 'SRG-APP-000277'
  tag fix_id: 'F-69033r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001241']
  tag nist: ['SI-3 c 1']
end
