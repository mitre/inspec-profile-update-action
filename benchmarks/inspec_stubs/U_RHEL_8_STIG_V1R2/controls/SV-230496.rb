control 'SV-230496' do
  title 'RHEL 8 must disable the stream control transmission (SCTP) protocol.'
  desc 'It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

Failing to disconnect unused protocols can result in a system compromise.

The Stream Control Transmission Protocol (SCTP) is a transport layer protocol, designed to support the idea of message-oriented communication, with several streams of messages within one connection. Disabling SCTP protects the system against exploitation of any flaws in its implementation.'
  desc 'check', 'Verify the operating system disables the ability to load the SCTP protocol kernel module.

$ sudo grep -ri SCTP /etc/modprobe.d/* | grep -i "/bin/true"

install SCTP /bin/true

If the command does not return any output, or the line is commented out, and use of the SCTP protocol is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding.

Verify the operating system disables the ability to use the SCTP protocol.

Check to see if the SCTP protocol is disabled with the following command:

$ sudo grep -ri SCTP /etc/modprobe.d/* | grep -i "blacklist"

blacklist SCTP

If the command does not return any output or the output is not "blacklist SCTP", and use of the SCTP protocol is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding.'
  desc 'fix', 'Configure the operating system to disable the ability to use the SCTP protocol kernel module.

Add or update the following lines in the file "/etc/modprobe.d/blacklist.conf":

install SCTP /bin/true
blacklist SCTP

Reboot the system for the settings to take effect.'
  impact 0.3
  ref 'DPMS Target Red Hat Enterprise Linux 8'
  tag check_id: 'C-33165r568234_chk'
  tag severity: 'low'
  tag gid: 'V-230496'
  tag rid: 'SV-230496r627750_rule'
  tag stig_id: 'RHEL-08-040023'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-33140r568235_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
