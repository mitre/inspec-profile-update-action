control 'SV-77567' do
  title 'The McAfee VirusScan Enterprise for Linux 1.9.x/2.0.x On-Access scanner must be configured to decompress archives when scanning.'
  desc 'Malware can be hidden within archived files and passed from system to system undetected unless the archive is decompressed and each file scanned.  By disabling the archive scanning capability, archives such as .tar and .tgz files will not be decompressed and any infected files in the archives would go undetected. Decompression can slow performance, however; any virus-infected file inside an archive cannot become active until it has been extracted. Recognizing the slow performance potential'
  desc 'check', 'From a desktop browser window, connect to the McAfee VirusScan Enterprise for Linux (VSEL) Monitor (WEB interface) of the Linux system being reviewed and logon with the nails user account.

In the VSEL WEB Monitor, under "Configure", select "On-Access Settings".
Under "Anti-virus Scanning Options", verify the "Decompress archives" check box is selected.

If the check box "Decompress archives" is not selected, this is a finding. 

If the check box for "Decompress archives" is not selected but the On-Demand scan decompress of archives is configured in the regularly scheduled scan, as specified in STIG ID DTAVSEL-101, this is a finding and severity of this can be dropped to a CAT 3.

To validate without the Web interface, access the Linux system being reviewed, either at the console or by a SSH connection.
At the command line, navigate to /var/opt/NAI/LinuxShield/etc.
Enter the command "grep "decompArchive" nailsd.cfg"

If the response given includes "nailsd.profile.OAS.decompArchive: false" or includes "nailsd.profile.OAS.decompArchive: true" with a preceding #,  this is a finding.'
  desc 'fix', 'From a desktop browser window, connect to the McAfee VirusScan Enterprise for Linux (VSEL) Monitor (WEB interface) of the Linux system being reviewed and logon with the nails user account.

In the VSEL WEB Monitor, under "Configure", select "On-Access Settings".
Under "Anti-virus Scanning Options", select the "Decompress archives" check box.
Click "Apply".'
  impact 0.5
  ref 'DPMS Target McAfee VSEL Local Client'
  tag check_id: 'C-63829r1_chk'
  tag severity: 'medium'
  tag gid: 'V-63077'
  tag rid: 'SV-77567r1_rule'
  tag stig_id: 'DTAVSEL-004'
  tag gtitle: 'SRG-APP-000279'
  tag fix_id: 'F-68995r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001243']
  tag nist: ['SI-3 c 2']
end
