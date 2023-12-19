control 'SV-77565' do
  title 'The McAfee VirusScan Enterprise for Linux 1.9.x/2.0.x must be configured to enable On-Access scanning.'
  desc "For anti-virus software to be effective, it must be running at all times, beginning from the point of the system's initial startup. Otherwise, the risk is greater for viruses, Trojans, and other malware infecting the system during that startup phase."
  desc 'check', 'Note: McAfee VSEL On-Access scan is not compatible with NFS Version 4. On client systems with the NFS 4.0 client as default, execute the following command to use NFS version 3.0 as a workaround:
mount -t nfs -o nfsvers=3 <NFS_Path> <Mount_point>

If mounting with NFS version 3.0 is not an option, this is a finding.

Only in such case, if STIG ID DTAVSEL-100 is configured for a daily scheduled scan and DTAVSEL-101 through DTAVSEL-114 are not a finding, the severity of this check can be reduced to a CAT 2.

From a desktop browser window, connect to the McAfee VirusScan Enterprise for Linux (VSEL) Monitor (WEB interface) of the Linux system being reviewed and logon with the nails user account.

In the VSEL WEB Monitor, under "Configure", select "On-Access Settings".
Under "Anti-virus Scanning Options", verify the "Enable On-Access scanning" check box is selected.
Verify the "Quarantine directory" field is populated with "/quarantine" (or another valid location as determined by the organization).

If the check box "Enable On-Access scanning" is not selected, this is a finding.
 
If the "Quarantine directory" field is not populated, this is a finding.

To validate without the Web interface, access the Linux system being reviewed, either at the console or by a SSH connection.
At the command line, navigate to /var/opt/NAI/LinuxShield/etc.
Enter the command "grep "oasEnabled" nailsd.cfg"

If the response given is "nailsd.oasEnabled: false" or is "nailsd.oasEnabled: true" with a preceding #, this is a finding.'
  desc 'fix', 'From a desktop browser window, connect to the McAfee VirusScan Enterprise for Linux (VSEL) Monitor (WEB interface) of the Linux system being reviewed and logon with the nails user account.

In the VSEL WEB Monitor, under "Configure", select "On-Access Settings".
Under "Anti-virus Scanning Options", select the "Enable On-Access scanning" check box.
In the "Quarantine directory" field, populate with "/quarantine" (or another valid location as determined by the organization).
Click "Apply".'
  impact 0.7
  ref 'DPMS Target McAfee VSEL Local Client'
  tag check_id: 'C-63827r1_chk'
  tag severity: 'high'
  tag gid: 'V-63075'
  tag rid: 'SV-77565r1_rule'
  tag stig_id: 'DTAVSEL-003'
  tag gtitle: 'SRG-APP-000279'
  tag fix_id: 'F-68993r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001243']
  tag nist: ['SI-3 c 2']
end
