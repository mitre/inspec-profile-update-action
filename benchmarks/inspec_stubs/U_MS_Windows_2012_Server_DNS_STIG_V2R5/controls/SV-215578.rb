control 'SV-215578' do
  title 'The validity period for the RRSIGs covering a zones DNSKEY RRSet must be no less than two days and no more than one week.'
  desc "The best way for a zone administrator to minimize the impact of a key compromise is by limiting the validity period of RRSIGs in the zone and in the parent zone. This strategy limits the time during which an attacker can take advantage of a compromised key to forge responses. An attacker that has compromised a ZSK can use that key only during the KSK's signature validity interval. An attacker that has compromised a KSK can use that key for only as long as the signature interval of the RRSIG covering the DS RR in the delegating parent. These validity periods should be short, which will require frequent re-signing.

To minimize the impact of a compromised ZSK, a zone administrator should set a signature validity period of 1 week for RRSIGs covering the DNSKEY RRSet in the zone (the RRSet that contains the ZSK and KSK for the zone). The DNSKEY RRSet can be re-signed without performing a ZSK rollover, but scheduled ZSK rollovers should still be performed at regular intervals."
  desc 'check', 'Note: This check is Not applicable for Windows 2012 DNS Servers that only host Active Directory integrated zones or for Windows 2012 DNS servers on a Classified network.

Log on to the DNS server using the account designated as Administrator or DNS Administrator.

Press Windows Key + R, execute dnsmgmt.msc.

On the opened DNS Manager snap-in from the left pane, expand the server name for the DNS server, and then expand Forward Lookup Zones.

From the expanded list, click to select the zone.

Right-click the zone and select DNSSEC, Properties.

Select the KSK Tab.

Verify the "DNSKEY signature validity period (hours):” is set to at least 48 hours and no more than 168 hours. 

Select the ZSK Tab. 
Verify the "DNSKEY signature validity period (hours):" is set to at least 48 hours and no more than 168 hours.

If either the KSK or ZSK Tab "DNSKEY signature validity period (hours):" values are set to less than 48 hours or more than 168 hours, this is a finding.'
  desc 'fix', 'Log on to the DNS server using the account designated as Administrator or DNS Administrator.

Press Windows Key + R, execute dnsmgmt.msc.

On the opened DNS Manager snap-in from the left pane, expand the server name for the DNS server, and then expand Forward Lookup Zones.

From the expanded list, click to select the zone.

Right-click the zone and select DNSSEC, Properties.

Select the KSK Tab. For the "DNSKEY RRSET signature validity period (hours):" setting, configure to a value between 48-168 hours. 

Select the ZSK Tab. For the "DNSKEY signature validity period (hours):" setting, configure to a value between 48-168 hours.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 2012 Server Domain Name System'
  tag check_id: 'C-16772r314209_chk'
  tag severity: 'medium'
  tag gid: 'V-215578'
  tag rid: 'SV-215578r561297_rule'
  tag stig_id: 'WDNS-CM-000008'
  tag gtitle: 'SRG-APP-000516-DNS-000078'
  tag fix_id: 'F-16770r314210_fix'
  tag 'documentable'
  tag legacy: ['SV-73019', 'V-58589']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
