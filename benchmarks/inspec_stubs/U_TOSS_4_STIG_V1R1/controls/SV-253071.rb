control 'SV-253071' do
  title 'TOSS must disable IEEE 1394 (FireWire) Support.'
  desc 'It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

The IEEE 1394 (FireWire) is a serial bus standard for high-speed real-time communication. Disabling FireWire protects the system against exploitation of any flaws in its implementation.'
  desc 'check', 'Verify the operating system disables the ability to load the firewire-core kernel module.

$ sudo grep -r firewire-core /etc/modprobe.d/* | grep install

install firewire-core /bin/false

If the command does not return any output, or the line is commented out, and use of the firewire-core protocol is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding.

Verify the operating system disables the ability to use the firewire-core kernel module.

Check to see if the firewire-core kernel module is disabled with the following command:

$ sudo grep -r firewire-core /etc/modprobe.d/* | grep "blacklist"

blacklist firewire-core

If the command does not return any output or the output is not "blacklist firewire-core", and use of the firewire-core kernel module is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding.'
  desc 'fix', 'Configure the operating system to disable the ability to use the firewire-core kernel module.

Add or update the following lines in the file "/etc/modprobe.d/blacklist.conf":

install firewire-core /bin/false
blacklist firewire-core

Reboot the system for the settings to take effect.'
  impact 0.5
  ref 'DPMS Target TOSS 4'
  tag check_id: 'C-56524r824883_chk'
  tag severity: 'medium'
  tag gid: 'V-253071'
  tag rid: 'SV-253071r824885_rule'
  tag stig_id: 'TOSS-04-040160'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-56474r824884_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
