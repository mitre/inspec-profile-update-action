control 'SV-251770' do
  title 'The NSX-T Tier-1 Gateway must be configured to have all inactive interfaces removed.'
  desc 'An inactive interface is rarely monitored or controlled and may expose a network to an undetected attack on that interface.

If an interface is no longer used, the configuration must be deleted.'
  desc 'check', 'From the NSX-T Manager web interface, go to Networking >> Tier-1 Gateways.

For every Tier-1 Gateway, expand the Tier-1 Gateway. Click on the number in the Linked Segments to review the currently linked segments.

For every Tier-1 Gateway, expand the Tier-1 Gateway. Expand Service Interfaces, then click on the number to review the Service Interfaces.

Review each interface or linked segment present to determine if they are not in use or inactive.

If there are any linked segments or service interfaces present on a Tier-1 Gateway that are not in use or inactive, this is a finding.'
  desc 'fix', 'To remove a stale linked segment from a Tier-1 Gateway, do the following:

From the NSX-T Manager web interface, go to Networking >> Segments and edit the target segment.

Under Connected Gateway, change to "None" and click "Save".

Note: The stale linked segment can also be deleted if there are no active workloads attached to it.

To remove a stale service interface from a Tier-1 Gateway, do the following:

From the NSX-T Manager web interface, go to Networking >> Tier-1 Gateways >> Edit the target Tier-1 Gateway.

Expand Service Interfaces >> click on the number to view the Service Interfaces.

On the stale service interface, select "Delete" and click "Delete" again to confirm.'
  impact 0.7
  ref 'DPMS Target VMware NSX-T Tier 1 Gateway RTR'
  tag check_id: 'C-55207r810208_chk'
  tag severity: 'high'
  tag gid: 'V-251770'
  tag rid: 'SV-251770r810210_rule'
  tag stig_id: 'T1RT-3X-000016'
  tag gtitle: 'SRG-NET-000019-RTR-000007'
  tag fix_id: 'F-55161r810209_fix'
  tag 'documentable'
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
