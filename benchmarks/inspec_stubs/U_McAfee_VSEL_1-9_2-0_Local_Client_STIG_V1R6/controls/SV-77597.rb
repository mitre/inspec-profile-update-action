control 'SV-77597' do
  title 'The McAfee VirusScan Enterprise for Linux 1.9.x/2.0.x On-Access scanner must be enabled to scan mounted volumes when mounted volumes point to a network server without an anti-virus solution installed.'
  desc 'Mounting network volumes to other network systems introduces a path for malware to be introduced. It is imperative to protect Linux systems from malware introduced from those other network systems by either ensuring the remote systems are protected or by scanning files from those systems when they are accessed.'
  desc 'check', %q(With the System Administrator's assistance, determine network mounted volumes on the Linux system being reviewed. 

If network mounted volumes are mounted, verify whether anti-virus protection is locally installed on, and configured to protect, the network servers to which the mounted volumes connect.

If all network servers to which mounted volumes connect are protected by locally installed and configured anti-virus protection, this check for the Linux system being reviewed is Not Applicable. 

If no network mounted volumes are configured on the Linux system being reviewed, this check is Not Applicable.

If mounted volumes exist on the Linux system being reviewed which are connecting to network servers which lack locally installed and configured anti-virus protection, this check must be validated. 

From a desktop browser window, connect to the McAfee VirusScan Enterprise for Linux (VSEL) Monitor (WEB interface) of the Linux system being reviewed and logon with the nails user account.

In the VSEL WEB Monitor, under "Configure", select "On-Access Settings".
Under "Anti-virus Scanning Options", verify check box for "Scan files on network mounted volumes" is selected.

If the check box for "Scan files on network mounted volumes" is not selected, this is a finding.

To validate without the Web interface, access the Linux system being reviewed, either at the console or by a SSH connection.
At the command line, navigate to /var/opt/NAI/LinuxShield/etc.
Enter the command "grep "nailsd.profile.OAS.scanNWFiles:" nailsd.cfg"

If the response given for "nailsd.profile.OAS.scanNWFiles" is not "true", this is a finding.)
  desc 'fix', 'From a desktop browser window, connect to the McAfee VirusScan Enterprise for Linux (VSEL) Monitor (WEB interface) of the Linux system being reviewed and logon with the nails user account.

In the VSEL WEB Monitor, under "Configure", select "On-Access Settings".
Under "Anti-virus Scanning Options", select the check box for "Scan files on network mounted volumes".

Click "Apply".'
  impact 0.5
  ref 'DPMS Target McAfee VSEL Local Client'
  tag check_id: 'C-63859r1_chk'
  tag severity: 'medium'
  tag gid: 'V-63107'
  tag rid: 'SV-77597r1_rule'
  tag stig_id: 'DTAVSEL-019'
  tag gtitle: 'SRG-APP-000278'
  tag fix_id: 'F-69025r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
