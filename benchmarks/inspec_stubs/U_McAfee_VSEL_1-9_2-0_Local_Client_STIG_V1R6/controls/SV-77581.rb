control 'SV-77581' do
  title 'The McAfee VirusScan Enterprise for Linux 1.9.x/2.0.x On-Access scanner maximum scan time must not be less than 45 seconds.'
  desc 'When anti-virus software is not configured to limit the amount of time spent trying to scan a file, the total effectiveness of the anti-virus software, and performance on the system being scanned, will be degraded. By limiting the amount of time the anti-virus software uses when scanning a file, the scan will be able to complete in a timely manner.

Although the description of this requirement indicates a "maximum scan time", the intent of this requirement is to explicitly set a maximum scan time without impacting the effectiveness of the scan. Left unconfigured, the scan could run indefinitely on one file. If configured with a value of less than 45 seconds, the scanning of some files will be skipped. If configured with 45 or more seconds, the success rate of files being completely scanned is higher.'
  desc 'check', 'From a desktop browser window, connect to the McAfee VirusScan Enterprise for Linux (VSEL) Monitor (WEB interface) of the Linux system being reviewed and logon with the nails user account.

In the VSEL WEB Monitor, under "Configure", select "On-Access Settings".
Under "Anti-virus Scanning Options", verify the "Maximum scan time (seconds)" is configured with at least "45" or more seconds.

If the "Maximum scan time (seconds)" is not configured with at least "45" or more seconds, this is a finding.

To validate without the Web interface, access the Linux system being reviewed, either at the console or by a SSH connection.
At the command line, navigate to /var/opt/NAI/LinuxShield/etc.
Enter the command "grep "scanMaxTmo" nailsd.cfg"

If the response given for "nailsd.profile.OAS_default.scanMaxTmo" is "44" or less, or if the response give for  "nailsd.profile.OAS.scanMaxTmo" is "45" or more but with a preceding #, this is a finding.'
  desc 'fix', 'From a desktop browser window, connect to the McAfee VirusScan Enterprise for Linux (VSEL) Monitor (WEB interface) of the Linux system being reviewed and logon with the nails user account.

In the VSEL WEB Monitor, under "Configure", select "On-Access Settings".
Under "Anti-virus Scanning Options", configure the "Maximum scan time (seconds)" with at least "45" or more seconds.

Click "Apply".'
  impact 0.5
  ref 'DPMS Target McAfee VSEL Local Client'
  tag check_id: 'C-63843r1_chk'
  tag severity: 'medium'
  tag gid: 'V-63091'
  tag rid: 'SV-77581r1_rule'
  tag stig_id: 'DTAVSEL-011'
  tag gtitle: 'SRG-APP-000279'
  tag fix_id: 'F-69009r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001243']
  tag nist: ['SI-3 c 2']
end
