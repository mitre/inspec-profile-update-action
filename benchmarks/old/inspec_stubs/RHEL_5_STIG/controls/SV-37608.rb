control 'SV-37608' do
  title 'The system must not respond to Internet Control Message Protocol v4 (ICMPv4) echoes sent to a broadcast address.'
  desc 'Responding to broadcast (ICMP) echoes facilitates network mapping and provides a vector for amplification attacks.'
  desc 'fix', 'Configure the system to not respond to ICMP ECHO_REQUESTs sent to broadcast addresses. Edit /etc/sysctl.conf and add a setting for "net.ipv4.icmp_echo_ignore_broadcasts=1" and reload the sysctls.

Procedure:
# echo "net.ipv4.icmp_echo_ignore_broadcasts=1" >> /etc/sysctl.conf
# sysctl -p'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-22410'
  tag rid: 'SV-37608r1_rule'
  tag stig_id: 'GEN003603'
  tag gtitle: 'GEN003603'
  tag fix_id: 'F-31641r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001551']
  tag nist: ['AC-4']
end
