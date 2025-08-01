control 'SV-226890' do
  title 'The system must not process ICMP timestamp requests.'
  desc 'The processing of Internet Control Message Protocol (ICMP) timestamp requests increases the attack surface of the system.'
  desc 'check', 'Determine the type of zone that you are currently securing.
# zonename

If the zone is not the global zone, determine if any interfaces are exclusive to the zone:
# dladm show-link

If the output indicates "insufficient privileges" then this requirement is not applicable.

If the zone is the global zone or the non-global zone has exclusive interfaces verify the system does not respond to ICMP timestamp requests.
# ndd /dev/ip ip_respond_to_timestamp

If the result is not 0, this is a finding.'
  desc 'fix', 'Disable ICMP timestamp responses on the system.
# ndd -set /dev/ip ip_respond_to_timestamp 0
Also add this command to a system startup script.'
  impact 0.3
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-29052r484954_chk'
  tag severity: 'low'
  tag gid: 'V-226890'
  tag rid: 'SV-226890r603265_rule'
  tag stig_id: 'GEN003602'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29040r484955_fix'
  tag 'documentable'
  tag legacy: ['V-22409', 'SV-26621']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
