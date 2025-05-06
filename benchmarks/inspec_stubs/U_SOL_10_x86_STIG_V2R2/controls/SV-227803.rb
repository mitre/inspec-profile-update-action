control 'SV-227803' do
  title 'The system must not send IPv4 ICMP redirects.'
  desc "ICMP redirect messages are used by routers to inform hosts that a more direct route exists for a particular destination.  These messages contain information from the system's route table that could reveal portions of the network topology."
  desc 'check', 'Determine the type of zone that you are currently securing.
# zonename

If the zone is not the global zone, determine if any interfaces are exclusive to the zone:
# dladm show-link

If the output indicates "insufficient privileges" then this requirement is not applicable.

If the zone is the global zone or the non-global zone has exclusive interfaces verify the system does not send IPv4 ICMP redirect messages.

Procedure:
# ndd /dev/ip ip_send_redirects

If the result is not 0, this is a finding.'
  desc 'fix', 'Configure the system to not send IPv4 ICMP redirect messages.

Procedure:
# ndd -set /dev/ip ip_send_redirects 0

Also add this command to a system startup script.'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29965r489763_chk'
  tag severity: 'medium'
  tag gid: 'V-227803'
  tag rid: 'SV-227803r603266_rule'
  tag stig_id: 'GEN003610'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29953r489764_fix'
  tag 'documentable'
  tag legacy: ['V-22417', 'SV-26632']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
