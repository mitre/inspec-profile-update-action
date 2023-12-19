control 'SV-77587' do
  title 'The McAfee VirusScan Enterprise for Linux 1.9.x/2.0.x On-Access scanner must be configured to Quarantine if first action fails when a virus or Trojan is detected.'
  desc 'Malware may have infected a file that is necessary to the user. By configuring the anti-virus software to first attempt cleaning the infected file, availability to the file is not sacrificed. If a cleaning attempt is not successful, however, deleting the file is the only safe option to ensure the malware is not introduced onto the system or network.'
  desc 'check', 'From a desktop browser window, connect to the McAfee VirusScan Enterprise for Linux (VSEL) Monitor (WEB interface) of the Linux system being reviewed and logon with the nails user account.

In the VSEL WEB Monitor, under "Configure", select "On-Access Settings".
Under "Anti-virus Actions", verify "Quarantine" is selected from the second drop-down list for "Actions for viruses and Trojans".

If "Quarantine" is not selected from the second drop-down list for "Actions for viruses and Trojans", this is a finding.

To validate without the Web interface, access the Linux system being reviewed, either at the console or by a SSH connection.
At the command line, navigate to /var/opt/NAI/LinuxShield/etc.
Enter the command: grep ‘nailsd.profile.OAS.action.App.secondary’ nailsd.cfg

If the response given for "nailsd.profile.OAS.action.App.secondary" is not "Quarantine", this is a finding.'
  desc 'fix', 'From a desktop browser window, connect to the McAfee VirusScan Enterprise for Linux (VSEL) Monitor (WEB interface) of the Linux system being reviewed and logon with the nails user account.

In the VSEL WEB Monitor, under "Configure", select "On-Access Settings".
Under "Anti-virus Actions", select "Quarantine" from the second drop-down list for "Actions for viruses and Trojans" if first action fails.

Click "Apply".'
  impact 0.5
  ref 'DPMS Target McAfee VSEL Local Client'
  tag check_id: 'C-63849r2_chk'
  tag severity: 'medium'
  tag gid: 'V-63097'
  tag rid: 'SV-77587r2_rule'
  tag stig_id: 'DTAVSEL-014'
  tag gtitle: 'SRG-APP-000279'
  tag fix_id: 'F-69015r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001243']
  tag nist: ['SI-3 c 2']
end
