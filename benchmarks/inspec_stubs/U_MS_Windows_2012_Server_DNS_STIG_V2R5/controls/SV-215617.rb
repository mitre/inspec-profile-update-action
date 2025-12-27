control 'SV-215617' do
  title 'The Windows 2012 DNS Server must enforce approved authorizations between DNS servers through the use of digital signatures in the RRSet.'
  desc 'A mechanism to detect and prevent unauthorized communication flow must be configured or provided as part of the system design. If information flow is not enforced based on approved authorizations, the system may become compromised. Information flow control regulates where information is allowed to travel within a system and between interconnected systems. The flow of all application information must be monitored and controlled so it does not introduce any unacceptable risk to the systems or data.

Application-specific examples of enforcement occur in systems that employ rule sets or establish configuration settings that restrict information system services or provide a message filtering capability based on message content (e.g., implementing key word searches or using document characteristics).

Applications providing information flow control must be able to enforce approved authorizations for controlling the flow of information between interconnected systems in accordance with applicable policy.

Within the context of DNS, this is applicable in terms of controlling the flow of DNS information between systems, such as DNS zone transfers.'
  desc 'check', 'Note: This check is Not applicable for Windows 2012 DNS Servers that only host Active Directory integrated zones or for Windows 2012 DNS servers on a Classified network.

Log on to the DNS server using the Domain Admin or Enterprise Admin account or Local Administrator account.

Press Windows Key + R, execute dnsmgmt.msc.

On the opened DNS Manager snap-in from the left pane, expand the server name for the DNS server, and then expand Forward Lookup Zones.

From the expanded list, click to select the zone. 

Review the records for the zone and ensure the complete RRSet of records are present: RRSIG, NSEC3, DNSKEY, indicating DNSSEC compliance.

If the RRSet of records are not in the zone, this is a finding.'
  desc 'fix', 'Sign, or re-sign, the hosted zone(s) on the DNS server being validated.

Log on to the DNS server using the Domain Admin or Enterprise Admin account or Local Administrator account.

Press Windows Key + R, execute dnsmgmt.msc.

On the opened DNS Manager snap-in from the left pane, expand the server name for the DNS server, and then expand Forward Lookup Zones.

From the expanded list, click to select the zone.
 
Right-click the zone (repeat for each hosted zone), point to DNSSEC, and then click Sign the Zone, either using approved saved parameters or approved custom parameters.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 2012 Server Domain Name System'
  tag check_id: 'C-16811r572257_chk'
  tag severity: 'medium'
  tag gid: 'V-215617'
  tag rid: 'SV-215617r561297_rule'
  tag stig_id: 'WDNS-SC-000009'
  tag gtitle: 'SRG-APP-000215-DNS-000003'
  tag fix_id: 'F-16809r572258_fix'
  tag 'documentable'
  tag legacy: ['SV-73097', 'V-58667']
  tag cci: ['CCI-001663']
  tag nist: ['SC-20 b']
end
