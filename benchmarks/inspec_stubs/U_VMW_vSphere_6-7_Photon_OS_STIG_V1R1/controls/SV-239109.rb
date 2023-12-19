control 'SV-239109' do
  title 'The Photon operating system must use TCP syncookies.'
  desc "A TCP SYN flood attack can cause a denial of service by filling a system's TCP connection table with connections in the SYN_RCVD state. Syncookies can be used to track a connection when a subsequent ACK is received, verifying the initiator is attempting a valid connection and is not a flood source. This feature is activated when a flood condition is detected and enables the system to continue servicing valid connection requests.

"
  desc 'check', 'At the command line, execute the following command:

# /sbin/sysctl -a --pattern /tcp_syncookies

Expected result:

net.ipv4.tcp_syncookies = 1

If the output does not match the expected result, this is a finding.'
  desc 'fix', 'At the command line, execute the following commands:

# sed -i -e "/^net.ipv4.tcp_syncookies/d" /etc/sysctl.conf
# echo net.ipv4.tcp_syncookies=1>>/etc/sysctl.conf'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 Photon OS'
  tag check_id: 'C-42320r675133_chk'
  tag severity: 'medium'
  tag gid: 'V-239109'
  tag rid: 'SV-239109r675135_rule'
  tag stig_id: 'PHTN-67-000037'
  tag gtitle: 'SRG-OS-000142-GPOS-00071'
  tag fix_id: 'F-42279r675134_fix'
  tag satisfies: ['SRG-OS-000142-GPOS-00071', 'SRG-OS-000420-GPOS-00186']
  tag 'documentable'
  tag cci: ['CCI-001095', 'CCI-002385']
  tag nist: ['SC-5 (2)', 'SC-5 a']
end
