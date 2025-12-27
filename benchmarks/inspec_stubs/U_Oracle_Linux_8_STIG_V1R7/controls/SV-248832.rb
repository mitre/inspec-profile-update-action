control 'SV-248832' do
  title 'OL 8 must disable the transparent inter-process communication (TIPC) protocol.'
  desc 'It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

Failing to disconnect unused protocols can result in a system compromise.

The Transparent Inter-Process Communication (TIPC) protocol is designed to provide communications between nodes in a cluster. Disabling TIPC protects the system against exploitation of any flaws in its implementation.'
  desc 'check', 'Verify the operating system disables the ability to load the TIPC protocol kernel module.

$ sudo grep -r tipc /etc/modprobe.d/* | grep "/bin/true"

install tipc /bin/true

If the command does not return any output, or the line is commented out, and use of the TIPC protocol is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding.

Verify the operating system disables the ability to use the TIPC protocol.

Determine if the TIPC protocol is disabled with the following command:

$ sudo grep -r tipc /etc/modprobe.d/* | grep "blacklist"

blacklist tipc

If the command does not return any output or the output is not "blacklist tipc", and use of the TIPC protocol is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding.'
  desc 'fix', 'Configure the operating system to disable the ability to use the TIPC protocol kernel module.

Add or update the following lines in the file "/etc/modprobe.d/blacklist.conf":

install tipc /bin/true
blacklist tipc

Reboot the system for the settings to take effect.'
  impact 0.3
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52266r818692_chk'
  tag severity: 'low'
  tag gid: 'V-248832'
  tag rid: 'SV-248832r818694_rule'
  tag stig_id: 'OL08-00-040024'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-52220r818693_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
