control 'SV-45722' do
  title 'The system must not respond to Internet Control Message Protocol v4 (ICMPv4) echoes sent to a broadcast address.'
  desc 'Responding to broadcast (ICMP) echoes facilitates network mapping and provides a vector for amplification attacks.'
  desc 'check', 'Verify the system does not respond to ICMP ECHO_REQUESTs set to broadcast addresses.

Procedure:
# cat /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts

If the result is not 1, this is a finding.'
  desc 'fix', 'Configure the system to not respond to ICMP ECHO_REQUESTs sent to broadcast addresses. Edit /etc/sysctl.conf and add a setting for "net.ipv4.icmp_echo_ignore_broadcasts=1" and reload the sysctls.

Procedure:
# echo "net.ipv4.icmp_echo_ignore_broadcasts=1" >> /etc/sysctl.conf
# sysctl -p'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43089r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22410'
  tag rid: 'SV-45722r1_rule'
  tag stig_id: 'GEN003603'
  tag gtitle: 'GEN003603'
  tag fix_id: 'F-39120r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001551']
  tag nist: ['AC-4']
end
