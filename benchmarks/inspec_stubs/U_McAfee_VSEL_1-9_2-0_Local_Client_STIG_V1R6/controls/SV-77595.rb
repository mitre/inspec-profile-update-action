control 'SV-77595' do
  title 'The McAfee VirusScan Enterprise for Linux 1.9.x/2.0.x On-Access scanner must be configured to allow access to files if scanning times out.'
  desc 'Anti-virus software is the most commonly used technical control for malware threat mitigation. Real-time scanning of files as they are read from disk is a crucial first line of defense from malware attacks.'
  desc 'check', 'From a desktop browser window, connect to the McAfee VirusScan Enterprise for Linux (VSEL) Monitor (WEB interface) of the Linux system being reviewed and logon with the nails user account.

In the VSEL WEB Monitor, under "Configure", select "On-Access Settings".
Under "Anti-virus Actions", verify the "Allow access" radio button is selected for "Action on timeout".

If the "Allow access" radio button is not selected for "Action on timeout", this is a finding.

To validate without the Web interface, access the Linux system being reviewed, either at the console or by a SSH connection.
At the command line, navigate to /var/opt/NAI/LinuxShield/etc.
Enter the command: grep ‘nailsd.profile.OAS.action.timeout ‘ nailsd.cfg

If the response given for "nailsd.profile.OAS.action.timeout" is not "Pass", this is a finding.'
  desc 'fix', 'From a desktop browser window, connect to the McAfee VirusScan Enterprise for Linux (VSEL) Monitor (WEB interface) of the Linux system being reviewed and logon with the nails user account.

In the VSEL WEB Monitor, under "Configure", select "On-Access Settings".
Under "Anti-virus Actions", select the "Allow access" radio button for "Action on timeout".

Click "Apply".'
  impact 0.5
  ref 'DPMS Target McAfee VSEL Local Client'
  tag check_id: 'C-63857r2_chk'
  tag severity: 'medium'
  tag gid: 'V-63105'
  tag rid: 'SV-77595r2_rule'
  tag stig_id: 'DTAVSEL-018'
  tag gtitle: 'SRG-APP-000279'
  tag fix_id: 'F-69023r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001243']
  tag nist: ['SI-3 c 2']
end
