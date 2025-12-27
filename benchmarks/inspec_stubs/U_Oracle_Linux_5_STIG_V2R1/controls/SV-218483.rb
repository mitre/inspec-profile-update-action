control 'SV-218483' do
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
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19958r555647_chk'
  tag severity: 'medium'
  tag gid: 'V-218483'
  tag rid: 'SV-218483r603259_rule'
  tag stig_id: 'GEN003604'
  tag gtitle: 'SRG-OS-000096-GPOS-00050'
  tag fix_id: 'F-19956r555648_fix'
  tag 'documentable'
  tag legacy: ['V-22411', 'SV-64195']
  tag cci: ['CCI-001503', 'CCI-001551', 'CCI-000382']
  tag nist: ['CM-6 d', 'AC-4', 'CM-7 b']
end
