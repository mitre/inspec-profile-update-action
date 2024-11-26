control 'SV-45723' do
  title 'The system must not respond to Internet Control Message Protocol (ICMP) timestamp requests sent to a broadcast address.'
  desc 'The processing of (ICMP) timestamp requests increases the attack surface of the system.  Responding to broadcast ICMP timestamp requests facilitates network mapping and provides a vector for amplification attacks.'
  desc 'check', 'Verify the system does not respond to ICMP TIMESTAMP_REQUESTs set to broadcast addresses.

Procedure:
# cat /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts

If the result is not 1, this is a finding.

Note: The same parameter controls both ICMP ECHO_REQUESTs and TIMESTAMP_REQUESTs.'
  desc 'fix', 'Configure the system to not respond to ICMP TIMESTAMP_REQUESTs sent to broadcast addresses. Edit /etc/sysctl.conf and add a setting for "net.ipv4.icmp_echo_ignore_broadcasts=1" and reload the sysctls.

Procedure:
# echo "net.ipv4.icmp_echo_ignore_broadcasts=1" >> /etc/sysctl.conf
# sysctl -p'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43090r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22411'
  tag rid: 'SV-45723r1_rule'
  tag stig_id: 'GEN003604'
  tag gtitle: 'GEN003604'
  tag fix_id: 'F-39121r1_fix'
  tag 'documentable'
  tag mitigations: 'GEN000000-FW'
  tag mitigation_control: "The system's firewall default-deny policy mitigates the risk from this vulnerability."
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001551']
  tag nist: ['AC-4']
end
