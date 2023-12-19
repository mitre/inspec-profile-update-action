control 'SV-77575' do
  title 'The McAfee VirusScan Enterprise for Linux 1.9.x/2.0.x On-Access scanner must be configured to scan files when being written to disk.'
  desc 'Anti-virus software is the most commonly used technical control for malware threat mitigation. Real-time scanning of files as they are written to disk is a crucial first line of defense from malware attacks.'
  desc 'check', 'From a desktop browser window, connect to the McAfee VirusScan Enterprise for Linux (VSEL) Monitor (WEB interface) of the Linux system being reviewed and logon with the nails user account.

In the VSEL WEB Monitor, under "Configure", select "On-Access Settings".
Under "Anti-virus Scanning Options", verify the "Scan files when writing to disk" check box is selected.

If the check box "Scan files when writing to disk" is not selected, this is a finding.

To validate without the Web interface, access the Linux system being reviewed, either at the console or by a SSH connection.
At the command line, navigate to /var/opt/NAI/LinuxShield/etc.
Enter the command "grep "scanOnWrite" nailsd.cfg"

If the response given is "nailsd.profile.OAS.scanOnWrite: false" or is "nailsd.profile.OAS.scanOnWrite: true" with a preceding #, this is a finding.'
  desc 'fix', 'From a desktop browser window, connect to the McAfee VirusScan Enterprise for Linux (VSEL) Monitor (WEB interface) of the Linux system being reviewed and logon with the nails user account.

In the VSEL WEB Monitor, under "Configure", select "On-Access Settings".
Under "Anti-virus Scanning Options", select the "Scan files when writing to disk" check box.

Click "Apply".'
  impact 0.5
  ref 'DPMS Target McAfee VSEL Local Client'
  tag check_id: 'C-63837r1_chk'
  tag severity: 'medium'
  tag gid: 'V-63085'
  tag rid: 'SV-77575r1_rule'
  tag stig_id: 'DTAVSEL-008'
  tag gtitle: 'SRG-APP-000279'
  tag fix_id: 'F-69003r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001243']
  tag nist: ['SI-3 c 2']
end
