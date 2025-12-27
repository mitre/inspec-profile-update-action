control 'SV-253074' do
  title 'TOSS must disable the asynchronous transfer mode (ATM) protocol.'
  desc 'It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

Failing to disconnect unused protocols can result in a system compromise.

The Asynchronous Transfer Mode (ATM) is a protocol operating on network, data link, and physical layers, based on virtual circuits and virtual paths. Disabling ATM protects the system against exploitation of any flaws in its implementation.'
  desc 'check', 'Verify the operating system disables the ability to load the ATM protocol kernel module.

$ sudo grep -r atm /etc/modprobe.d/* | grep install

install atm /bin/false

If the command does not return any output, or the line is commented out, and use of the ATM protocol is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding.

Verify the operating system disables the ability to use the ATM protocol.

Check to see if the ATM protocol is disabled with the following command:

$ sudo grep -r atm /etc/modprobe.d/* | grep "blacklist"

blacklist atm

If the command does not return any output or the output is not "blacklist atm", and use of the ATM protocol is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding.'
  desc 'fix', 'Configure the operating system to disable the ability to use the ATM protocol kernel module.

Add or update the following lines in the file "/etc/modprobe.d/blacklist.conf":

install atm /bin/false
blacklist atm

Reboot the system for the settings to take effect.'
  impact 0.5
  ref 'DPMS Target TOSS 4'
  tag check_id: 'C-56527r824892_chk'
  tag severity: 'medium'
  tag gid: 'V-253074'
  tag rid: 'SV-253074r824894_rule'
  tag stig_id: 'TOSS-04-040190'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-56477r824893_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
