control 'SV-77281' do
  title 'The McAfee VirusScan Enterprise for Linux  Web interface must be disabled unless the system is on a segregated network.'
  desc 'The McAfee VirusScan Enterprise for Linux WEB GUI is the method for configuring the McAfee VSEL on a non-managed Linux system. The WEB GUI on the system could be used maliciously to gain unauthorized access to the system. By restricting access to interface by implementing firewall rules, the risk of unauthorized access will be mitigated.'
  desc 'check', 'Verify the location of the system being reviewed. If it is on a segregated network, without access to the Internet nor access to the Local Area Network, nor is it managed by a McAfee ePO server, this check is Not Applicable.

If the system being reviewed has access to the Internet, is reachable from the Local Area Network and/or is managed by a McAfee ePO server, this check must be validated.

To validate without the Web interface, access the Linux system being reviewed, either at the console or by a SSH connection.

At the command line, navigate to /var/opt/NAI/LinuxShield/etc.
Enter the command "grep "nailsd.disableCltWebUI" nailsd.cfg".

If the response given for "nailsd.disableCltWebUI" is "false", this is a finding.'
  desc 'fix', 'To validate without the Web interface, access the Linux system being reviewed, either at the console or by a SSH connection.

At the command line, navigate to /var/opt/NAI/LinuxShield/etc.

Modify the nailsd.cfg file.
Find the line "nailsd.disableCltWebUI: false"
Change the "false" to "true".

Reload the nails processes by running the following command: 
/etc/init.d/nails reload'
  impact 0.5
  ref 'DPMS Target McAfee VSEL Local Client'
  tag check_id: 'C-63599r1_chk'
  tag severity: 'medium'
  tag gid: 'V-62791'
  tag rid: 'SV-77281r1_rule'
  tag stig_id: 'DTAVSEL-000'
  tag gtitle: 'SRG-APP-000380'
  tag fix_id: 'F-68711r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001813']
  tag nist: ['CM-5 (1) (a)']
end
