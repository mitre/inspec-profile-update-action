control 'SV-77579' do
  title 'The McAfee VirusScan Enterprise for Linux 1.9.x/2.0.x On-Access scanner must be configured to scan all file types.'
  desc 'When scanning for malware, excluding specific file types will increase the risk of a malware-infected file going undetected. By configuring anti-virus software to scan all file types, the scanner has a higher success rate at detecting and eradicating malware.'
  desc 'check', 'From a desktop browser window, connect to the McAfee VirusScan Enterprise for Linux (VSEL) Monitor (WEB interface) of the Linux system being reviewed and logon with the nails user account.

In the VSEL WEB Monitor, under "Configure", select "On-Access Settings".
Under "Extension Base Scanning", verify the "Scan all files" radio button is selected.

If the radio button "Scan all files" is not selected, this is a finding.

To validate without the Web interface, access the Linux system being reviewed, either at the console or by a SSH connection.
At the command line, navigate to /var/opt/NAI/LinuxShield/etc.
Enter the command "grep "allFiles" nailsd.cfg"

If the response given is "nailsd.profile.OAS.allFiles: false" or is "nailsd.profile.OAS.allFiles: true" with a preceding #, this is a finding.'
  desc 'fix', 'From a desktop browser window, connect to the McAfee VirusScan Enterprise for Linux (VSEL) Monitor (WEB interface) of the Linux system being reviewed and logon with the nails user account.

In the VSEL WEB Monitor, under "Configure", select "On-Access Settings".
Select the "Edit" button.
Under "Extension Base Scanning", select the "Scan all files" radio button.

Click "Apply".'
  impact 0.5
  ref 'DPMS Target McAfee VSEL Local Client'
  tag check_id: 'C-63841r1_chk'
  tag severity: 'medium'
  tag gid: 'V-63089'
  tag rid: 'SV-77579r1_rule'
  tag stig_id: 'DTAVSEL-010'
  tag gtitle: 'SRG-APP-000279'
  tag fix_id: 'F-69007r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001243']
  tag nist: ['SI-3 c 2']
end
