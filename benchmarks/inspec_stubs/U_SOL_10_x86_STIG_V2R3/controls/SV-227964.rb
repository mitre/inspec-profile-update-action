control 'SV-227964' do
  title 'The system must not send IPv6 ICMP redirects.'
  desc "ICMP redirect messages are used by routers to inform hosts that a more direct route exists for a particular destination. These messages contain information from the system's route table revealing  portions of the network topology."
  desc 'check', 'Determine the type of zone that you are currently securing.
# zonename

If the zone is not the global zone, determine if any interfaces are exclusive to the zone:
# dladm show-link

If the output indicates "insufficient privileges" then this requirement is not applicable.

If the zone is the global zone or the non-global zone has exclusive interfaces verify the system is configured to not send IPv6 ICMP redirect messages.
# ndd /dev/ip6 ip6_send_redirects

If the returned value is not 0, this is a finding.'
  desc 'fix', 'Configure the system to not send IPv6 ICMP redirect messages.
# ndd -set /dev/ip6 ip6_send_redirects 0

Also, add this command to a system startup script.'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-30126r490327_chk'
  tag severity: 'medium'
  tag gid: 'V-227964'
  tag rid: 'SV-227964r603266_rule'
  tag stig_id: 'GEN007880'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-30114r490328_fix'
  tag 'documentable'
  tag legacy: ['V-22551', 'SV-26938']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
