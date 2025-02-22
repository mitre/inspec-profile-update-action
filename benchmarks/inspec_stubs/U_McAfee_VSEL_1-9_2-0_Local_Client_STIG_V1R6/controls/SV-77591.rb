control 'SV-77591' do
  title 'The McAfee VirusScan Enterprise for Linux 1.9.x/2.0.x On-Access scanner must be configured to Quarantine if first action fails when programs and jokes are found.'
  desc 'Potentially Unwanted Programs (PUPs) include Spyware, Adware, Remote Administration Tools, Dialers, Password Crackers, Jokes, and Key Loggers. While PUPs do not typically have any infection capability on their own, they rely on malware or other attach mechanisms to be installed onto target hosts, after which they will collect and transfer data from the host to an external host and/or will be used as attach mechanisms. Configuring the anti-virus software to attempt to clean the file first will allow for the possibility of a false positive. In most cases, however, the secondary action of delete will be used, mitigating the risk of the PUPs being installed and used maliciously.'
  desc 'check', 'From a desktop browser window, connect to the McAfee VirusScan Enterprise for Linux (VSEL) Monitor (WEB interface) of the Linux system being reviewed and logon with the nails user account.

In the VSEL WEB Monitor, under "Configure", select "On-Access Settings".
Under "Anti-virus Actions", verify "Quarantine" is selected from the second drop-down list for "Actions for Programs and Jokes".

If "Quarantine" is not selected from the second drop-down list for "Actions for Programs and Jokes", this is a finding.

To validate without the Web interface, access the Linux system being reviewed, either at the console or by a SSH connection.
At the command line, navigate to /var/opt/NAI/LinuxShield/etc.
Enter the command: grep ‘nailsd.profile.OAS.action.Default.secondary ‘ nailsd.cfg

If the response given for "nailsd.profile.OAS.action.Default.secondary" is not "Quarantine", this is a finding.'
  desc 'fix', 'From a desktop browser window, connect to the McAfee VirusScan Enterprise for Linux (VSEL) Monitor (WEB interface) of the Linux system being reviewed and logon with the nails user account.

In the VSEL WEB Monitor, under "Configure", select "On-Access Settings".
Under "Anti-virus Actions", select "Quarantine" from the second drop-down list for "Actions for Programs and Jokes" if first action fails.

Click "Apply".'
  impact 0.5
  ref 'DPMS Target McAfee VSEL Local Client'
  tag check_id: 'C-63853r2_chk'
  tag severity: 'medium'
  tag gid: 'V-63101'
  tag rid: 'SV-77591r2_rule'
  tag stig_id: 'DTAVSEL-016'
  tag gtitle: 'SRG-APP-000279'
  tag fix_id: 'F-69019r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001243']
  tag nist: ['SI-3 c 2']
end
