control 'SV-251751' do
  title 'The NSX-T Tier-0 Gateway must be configured to implement message authentication for all control plane protocols.'
  desc %q(A rogue router could send a fictitious routing update to convince a site's perimeter router to send traffic to an incorrect or even a rogue destination. This diverted traffic could be analyzed to learn confidential information about the site's network or used to disrupt the network's ability to communicate with other networks. This is known as a "traffic attraction attack" and is prevented by configuring neighbor router authentication for routing updates.)
  desc 'check', 'If the Tier-0 Gateway is not using BGP or OSPF, this is Not Applicable.

Since the NSX-T Tier-0 Gateway does not reveal if a BGP password is configured, interview the router administrator to determine if a password is configured on BGP neighbors.

If BGP neighbors do not have a password configured, this is a finding.

To verify OSPF areas are using authentication do the following:

From the NSX-T Manager web interface, go to Networking >> Tier-0 Gateways.

For every Tier-0 Gateway expand the "Tier-0 Gateway".

Expand "OSPF", click the number next to Area Definition, and view the Authentication field for each area.

If OSPF area definitions do not have Password or MD5 set for authentication, this is a finding.

Note: OSPF support was introduced in version 3.1.1.'
  desc 'fix', 'To set authentication for BGP neighbors do the following:

From the NSX-T Manager web interface, go to Networking >> Tier-0 Gateways, and expand the target Tier-0 gateway.

Expand BGP. Next to BGP Neighbors, click on the number present to open the dialog, then select "Edit" on the target BGP Neighbor.

Under Timers & Password, enter a password up to 20 characters, and then click "Save".

To set authentication for OSPF Area definitions do the following:

From the NSX-T Manager web interface, go to Networking >> Tier-0 Gateways, and expand the target Tier-0 gateway.

Expand OSPF. Next to Area Definition, click on the number present to open the dialog, and then select "Edit" on the target OSPF Area.

Change the Authentication drop-down to Password or MD5, enter a Key ID and/or Password, and then click "Save".'
  impact 0.5
  ref 'DPMS Target VMware NSX-T Tier-0 Gateway RTR'
  tag check_id: 'C-55188r810135_chk'
  tag severity: 'medium'
  tag gid: 'V-251751'
  tag rid: 'SV-251751r856692_rule'
  tag stig_id: 'T0RT-3X-000054'
  tag gtitle: 'SRG-NET-000230-RTR-000001'
  tag fix_id: 'F-55142r810136_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-002205']
  tag nist: ['CM-6 b', 'AC-4 (17)']
end
