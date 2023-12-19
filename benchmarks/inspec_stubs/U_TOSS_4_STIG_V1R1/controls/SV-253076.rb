control 'SV-253076' do
  title 'TOSS must disable the stream control transmission (SCTP) protocol.'
  desc 'It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

Failing to disconnect unused protocols can result in a system compromise.

The Stream Control Transmission Protocol (SCTP) is a transport layer protocol, designed to support the idea of message-oriented communication, with several streams of messages within one connection. Disabling SCTP protects the system against exploitation of any flaws in its implementation.'
  desc 'check', 'Verify the operating system disables the ability to load the SCTP protocol kernel module.

$ sudo grep -r sctp /etc/modprobe.d/* | grep install

install sctp /bin/false

If the command does not return any output, or the line is commented out, and use of the SCTP protocol is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding.

Verify the operating system disables the ability to use the SCTP protocol.

Check to see if the SCTP protocol is disabled with the following command:

$ sudo grep -r sctp /etc/modprobe.d/* | grep "blacklist"

blacklist sctp

If the command does not return any output or the output is not "blacklist sctp", and use of the SCTP protocol is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding.'
  desc 'fix', 'Configure the operating system to disable the ability to use the SCTP protocol kernel module.

Add or update the following lines in the file "/etc/modprobe.d/blacklist.conf":

install sctp /bin/false
blacklist sctp

Reboot the system for the settings to take effect.'
  impact 0.5
  ref 'DPMS Target TOSS 4'
  tag check_id: 'C-56529r824898_chk'
  tag severity: 'medium'
  tag gid: 'V-253076'
  tag rid: 'SV-253076r824900_rule'
  tag stig_id: 'TOSS-04-040210'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-56479r824899_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
