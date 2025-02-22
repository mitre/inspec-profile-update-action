control 'SV-253075' do
  title 'TOSS must disable the controller area network (CAN) protocol.'
  desc 'It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

Failing to disconnect unused protocols can result in a system compromise.

The Controller Area Network (CAN) is a serial communications protocol, which was initially developed for automotive and is now also used in marine, industrial, and medical applications. Disabling CAN protects the system against exploitation of any flaws in its implementation.'
  desc 'check', 'Verify the operating system disables the ability to load the CAN protocol kernel module.

$ sudo grep -r can /etc/modprobe.d/* | grep install

install can /bin/false

If the command does not return any output, or the line is commented out, and use of the CAN protocol is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding.

Verify the operating system disables the ability to use the CAN protocol.

Check to see if the CAN protocol is disabled with the following command:

$ sudo grep -r can /etc/modprobe.d/* | grep "blacklist"

blacklist can

If the command does not return any output or the output is not "blacklist can", and use of the CAN protocol is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding.'
  desc 'fix', 'Configure the operating system to disable the ability to use the CAN protocol kernel module.

Add or update the following lines in the file "/etc/modprobe.d/blacklist.conf":

install can /bin/false
blacklist can

Reboot the system for the settings to take effect.'
  impact 0.5
  ref 'DPMS Target TOSS 4'
  tag check_id: 'C-56528r824895_chk'
  tag severity: 'medium'
  tag gid: 'V-253075'
  tag rid: 'SV-253075r824897_rule'
  tag stig_id: 'TOSS-04-040200'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-56478r824896_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
