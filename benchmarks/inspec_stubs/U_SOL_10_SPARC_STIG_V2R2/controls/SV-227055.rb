control 'SV-227055' do
  title 'The system must ignore IPv6 ICMP redirect messages.'
  desc "ICMP redirect messages are used by routers to inform hosts that a more direct route exists for a particular destination. These messages modify the host's route table and are unauthenticated. An illicit ICMP redirect message could result in a man-in-the-middle attack."
  desc 'check', 'Determine the type of zone that you are currently securing.
# zonename

If the zone is not the global zone, determine if any interfaces are exclusive to the zone:
# dladm show-link

If the output indicates "insufficient privileges" then this requirement is not applicable.

If the zone is the global zone or the non-global zone has exclusive interfaces verify the system is configured to ignore IPv6 ICMP redirect messages.
# ndd /dev/ip6 ip6_ignore_redirect

If the returned value is not 1, this is a finding.'
  desc 'fix', 'Configure the system to ignore IPv6 ICMP redirect messages.
# ndd -set /dev/ip6 ip6_ignore_redirect 1
Also add this command to a system startup script.'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-29217r485537_chk'
  tag severity: 'medium'
  tag gid: 'V-227055'
  tag rid: 'SV-227055r603265_rule'
  tag stig_id: 'GEN007860'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29205r485538_fix'
  tag 'documentable'
  tag legacy: ['V-22550', 'SV-26937']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
