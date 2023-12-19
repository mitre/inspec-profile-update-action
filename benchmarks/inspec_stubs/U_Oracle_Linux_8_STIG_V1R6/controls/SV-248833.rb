control 'SV-248833' do
  title 'OL 8 must disable mounting of cramfs.'
  desc 'It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

Removing support for unneeded filesystem types reduces the local attack surface of the server.

Compressed ROM/RAM file system (or cramfs) is a read-only file system designed for simplicity and space-efficiency. It is mainly used in embedded and small-footprint systems.'
  desc 'check', 'Verify the operating system disables the ability to load the cramfs kernel module.

$ sudo grep -ri cramfs /etc/modprobe.d/* | grep -i "/bin/true"

install cramfs /bin/true

If the command does not return any output, or the line is commented out, and use of the cramfs protocol is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding.

Verify the operating system disables the ability to use the cramfs kernel module.

Determine if the cramfs kernel module is disabled with the following command:

$ sudo grep -ri cramfs /etc/modprobe.d/* | grep -i "blacklist"

blacklist cramfs

If the command does not return any output or the output is not "blacklist cramfs", and use of the cramfs kernel module is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding.'
  desc 'fix', 'Configure the operating system to disable the ability to use the cramfs kernel module.

Add or update the following lines in the file "/etc/modprobe.d/blacklist.conf":

install cramfs /bin/true
blacklist cramfs

Reboot the system for the settings to take effect.'
  impact 0.3
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52267r780063_chk'
  tag severity: 'low'
  tag gid: 'V-248833'
  tag rid: 'SV-248833r780065_rule'
  tag stig_id: 'OL08-00-040025'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-52221r780064_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
