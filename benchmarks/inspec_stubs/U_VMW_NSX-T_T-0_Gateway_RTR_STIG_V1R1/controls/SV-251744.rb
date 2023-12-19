control 'SV-251744' do
  title 'The NSX-T Tier-0 Gateway must be configured to reject inbound route advertisements for any prefixes belonging to the local autonomous system (AS).'
  desc 'Accepting route advertisements belonging to the local AS can result in traffic looping or being black holed, or at a minimum using a non-optimized path.'
  desc 'check', 'If the Tier-0 Gateway is not using eBGP, this is Not Applicable.

From the NSX-T Manager web interface, go to Networking >> Tier-0 Gateways.

For every Tier-0 Gateway, expand Tier-0 Gateway >>BGP. Near to BGP Neighbors, click on the number present to open the dialog.

For each neighbor examine any router filters to determine if any inbound route filters are applied.

If the In Filter is not configured with a prefix list that rejects prefixes belonging to the local AS, this is a finding.'
  desc 'fix', 'To configure a route filter do the following:

From the NSX-T Manager web interface, go to Networking >> Tier-0 Gateways >> edit the target Tier-0 gateway.

Expand Routing and open the IP Prefix List dialog. Edit an existing, or add a new prefix list that contains the prefixes belonging to the local AS to deny them. Click "Save".

To apply a route filter to a BGP neighbor do the following:

From the NSX-T Manager web interface, go to Networking >> Tier-0 Gateways and edit the target Tier-0 gateway.

Expand BGP, and next to BGP Neighbors, click on the number present to open the dialog. Select "Edit" on the target BGP Neighbor.

Open the router filter dialog and add or edit an existing router filter. Configure the In Filter with the filter previously created and click "Save", "Add", "Apply", and "Save".'
  impact 0.5
  ref 'DPMS Target VMware NSX-T Tier-0 Gateway RTR'
  tag check_id: 'C-55181r810114_chk'
  tag severity: 'medium'
  tag gid: 'V-251744'
  tag rid: 'SV-251744r810116_rule'
  tag stig_id: 'T0RT-3X-000003'
  tag gtitle: 'SRG-NET-000018-RTR-000003'
  tag fix_id: 'F-55135r810115_fix'
  tag 'documentable'
  tag cci: ['CCI-001368']
  tag nist: ['AC-4']
end
