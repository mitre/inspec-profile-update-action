control 'SV-226895' do
  title 'The system must not accept source-routed IPv4 packets.'
  desc 'Source-routed packets allow the source of the packet to suggest that routers forward the packet along a different path than configured on the router, which can be used to bypass network security measures.  This requirement applies only to the handling of source-routed traffic destined to the system itself, not to traffic forwarded by the system to another, such as when IPv4 forwarding is enabled and the system is functioning as a router.'
  desc 'check', 'Determine the type of zone that you are currently securing.
# zonename

If the zone is not the global zone, determine if any interfaces are exclusive to the zone:
# dladm show-link

If the output indicates "insufficient privileges" then this requirement is not applicable.

If the zone is the global zone or the non-global zone has exclusive interfaces check the system for an IPF rule blocking incoming source-routed packets. 

Procedure: # ipfstat -i 
 
Examine the list for rules such as: 
block in log quick all with opt lsrr
block in log quick all with opt ssrr

If the listed rules do not block incoming traffic with both lsrr and ssrr options, this is a finding.'
  desc 'fix', 'Edit /etc/ipf/ipf.conf and add rules to block incoming source-routed packets, such as: 

block in log quick all with opt lsrr 
block in log quick all with opt ssrr

Reload the IPF rules.
Procedure:
# ipf -Fa -A -f /etc/ipf/ipf.conf'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-29057r484969_chk'
  tag severity: 'medium'
  tag gid: 'V-226895'
  tag rid: 'SV-226895r603265_rule'
  tag stig_id: 'GEN003607'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29045r484970_fix'
  tag 'documentable'
  tag legacy: ['SV-29711', 'V-22414']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
