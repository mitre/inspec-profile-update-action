control 'SV-239184' do
  title 'The Photon operating system must send TCP timestamps.'
  desc 'TCP timestamps are used to provide protection against wrapped sequence numbers. It is possible to calculate system uptime (and boot time) by analyzing TCP timestamps. These calculated uptimes can help a bad actor in determining likely patch levels for vulnerabilities.'
  desc 'check', 'At the command line, execute the following command:

# /sbin/sysctl -a --pattern "net.ipv4.tcp_timestamps$"

Expected result:

net.ipv4.tcp_timestamps = 1

If the output does not match the expected result, this is a finding.'
  desc 'fix', 'At the command line, execute the following commands:

# sed -i -e "/^net.ipv4.tcp_timestamps/d" /etc/sysctl.conf
# echo net.ipv4.tcp_timestamps=1>>/etc/sysctl.conf'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 Photon OS'
  tag check_id: 'C-42395r675358_chk'
  tag severity: 'medium'
  tag gid: 'V-239184'
  tag rid: 'SV-239184r675360_rule'
  tag stig_id: 'PHTN-67-000113'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-42354r675359_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
