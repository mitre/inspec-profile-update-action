control 'WDNS-22-000052_rule' do
  title 'The Windows 2022 DNS Server must enforce approved authorizations between DNS servers using digital signatures in the Resource Record Set (RRSet).'
  desc 'A mechanism to detect and prevent unauthorized communication flow must be configured or provided as part of the system design. If information flow is not enforced based on approved authorizations, the system may become compromised. Information flow control regulates where information is allowed to travel within a system and between interconnected systems. The flow of all application information must be monitored and controlled so it does not introduce any unacceptable risk to the systems or data.

Application-specific examples of enforcement occur in systems that employ rule sets or establish configuration settings that restrict information system services or provide a message filtering capability based on message content (e.g., implementing key word searches or using document characteristics).

Applications providing information flow control must be able to enforce approved authorizations for controlling the flow of information between interconnected systems in accordance with applicable policy.

Within the context of DNS, this is applicable in terms of controlling the flow of DNS information between systems, such as DNS zone transfers.'
  desc 'check', 'Note: This check is not applicable for Windows 2022 DNS Servers that host only Active Directory-integrated zones or for Windows 2022 DNS Servers on a classified network.

Log on to the DNS server using the Domain Admin or Enterprise Admin account or Local Administrator account.

Press the Windows key + R and execute "dnsmgmt.msc".

On the opened DNS Manager snap-in from the left pane, expand the server name for the DNS server and then expand "Forward Lookup Zones".

From the expanded list, click to select the zone. 

Review the records for the zone and ensure the complete RRSet of records is present: RRSIG, NSEC3, DNSKEY, indicating DNSSEC compliance.

If the RRSet of records is not in the zone, this is a finding.'
  desc 'fix', 'Sign or re-sign the hosted zone(s) on the DNS server being validated.

Log on to the DNS server using the Domain Admin or Enterprise Admin account or Local Administrator account.

Press the Windows key + R and execute "dnsmgmt.msc".

On the opened DNS Manager snap-in from the left pane, expand the server name for the DNS server and then expand "Forward Lookup Zones".

From the expanded list, click to select the zone.
 
Right-click the zone (repeat for each hosted zone), point to DNSSEC, and then click "Sign the Zone" using either approved saved parameters or approved custom parameters.'
  impact 0.5
  tag check_id: 'C-WDNS-22-000052_chk'
  tag severity: 'medium'
  tag gid: 'WDNS-22-000052'
  tag rid: 'WDNS-22-000052_rule'
  tag stig_id: 'WDNS-22-000052'
  tag gtitle: 'SRG-APP-000215-DNS-000003'
  tag fix_id: 'F-WDNS-22-000052_fix'
  tag 'documentable'
  tag cci: ['CCI-001663']
  tag nist: ['SC-20 b']
end
