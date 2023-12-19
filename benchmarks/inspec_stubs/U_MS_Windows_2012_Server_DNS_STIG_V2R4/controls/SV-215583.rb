control 'SV-215583' do
  title 'The Windows 2012 DNS Server must be configured to enable DNSSEC Resource Records.'
  desc "The specification for a digital signature mechanism in the context of the DNS infrastructure is in IETF's DNSSEC standard.  In DNSSEC, trust in the public key (for signature verification) of the source is established not by going to a third party or a chain of third parties (as in public key infrastructure [PKI] chaining), but by starting from a trusted zone (such as the root zone) and establishing the chain of trust down to the current source of response through successive verifications of signature of the public key of a child by its parent. The public key of the trusted zone is called the trust anchor. After authenticating the source, the next process DNSSEC calls for is to authenticate the response. DNSSEC mechanisms involve two main processes: sign and serve, and verify signature.

Before a DNSSEC-signed zone can be deployed, a name server must be configured to enable DNSSEC processing."
  desc 'check', 'Note: This check is Not applicable for Windows 2012 DNS Servers that only host Active Directory integrated zones or for Windows 2012 DNS servers on a Classified network.

Log on to the DNS server using the Domain Admin or Enterprise Admin account or Local Administrator account.

Press Windows Key + R, execute dnsmgmt.msc.

On the opened DNS Manager snap-in from the left pane, expand the server name for the DNS server, and then expand Forward Lookup Zones.

From the expanded list, click to select each zone.
 
Review the RRs for each zone and verify all of the DNSEC record types are included for the zone. 

NOTE: The DS (Delegation Signer)record should also exist but the requirement for it is validated under WDNS-SC-000011.

RRSIG (Resource Read Signature)
DNSKEY (Public Key)
NSEC3 (Next Secure 3)

If the zone does not show all of the DNSSEC record types, this is a finding.'
  desc 'fix', 'Sign, or re-sign, the hosted zone(s) on the DNS server being validated.

Log on to the DNS server using the Domain Admin or Enterprise Admin account or Local Administrator account.

Press Windows Key + R, execute dnsmgmt.msc.

On the opened DNS Manager snap-in from the left pane, expand the server name for the DNS server, and then expand Forward Lookup Zones.

From the expanded list, right-click to select the zone (repeat for each hosted zone), point to DNSSEC, and then click Sign the Zone, either using approved saved parameters or approved custom parameters.'
  impact 0.7
  ref 'DPMS Target Microsoft Windows 2012 Server Domain Name System'
  tag check_id: 'C-16777r572209_chk'
  tag severity: 'high'
  tag gid: 'V-215583'
  tag rid: 'SV-215583r561297_rule'
  tag stig_id: 'WDNS-CM-000014'
  tag gtitle: 'SRG-APP-000516-DNS-000089'
  tag fix_id: 'F-16775r572210_fix'
  tag 'documentable'
  tag legacy: ['SV-73029', 'V-58599']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
