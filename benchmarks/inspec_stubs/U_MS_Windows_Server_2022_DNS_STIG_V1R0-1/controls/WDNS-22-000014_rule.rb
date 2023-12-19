control 'WDNS-22-000014_rule' do
  title "The validity period for the Resource Record Signatures (RRSIGs) covering a zone's DNSKEY RRSet must be no less than two days and no more than one week."
  desc "The best way for a zone administrator to minimize the impact of a key compromise is by limiting the validity period of RRSIGs in the zone and the parent zone. This strategy limits the time during which an attacker can take advantage of a compromised key to forge responses. An attacker that has compromised a zone signing key (ZSK) can use that key only during the key signing key's (KSK's) signature validity interval. An attacker that has compromised a KSK can use that key for only as long as the signature interval of the RRSIG covering the Delegation Signer (DS) Resource Record (RR) in the delegating parent. These validity periods should be short, which will require frequent re-signing.

To minimize the impact of a compromised ZSK, a zone administrator should set a signature validity period of one week for RRSIGs covering the DNSKEY RRSet in the zone (the RRSet that contains the ZSK and KSK for the zone). The DNSKEY RRSet can be re-signed without performing a ZSK rollover, but scheduled ZSK rollovers should still be performed at regular intervals."
  desc 'check', 'Note: This check is not applicable for Windows 2022 DNS Servers that host only Active Directory-integrated zones or Windows 2022 DNS Servers on a classified network.

Log on to the DNS server using the account designated as Administrator or DNS Administrator.

Press the Windows key + R and execute "dnsmgmt.msc".

On the opened DNS Manager snap-in from the left pane, expand the server name for the DNS server and then expand "Forward Lookup Zones".

From the expanded list, click to select the zone.

Right-click the zone and select DNSSEC >> Properties.

Select the "KSK" tab.

Verify the "DNSKEY signature validity period (hours):" is set to at least 48 hours and no more than 168 hours. 

Select the "ZSK" tab. 

Verify the "DNSKEY signature validity period (hours):" is set to at least 48 hours and no more than 168 hours.

If either the "KSK" or "ZSK" tab "DNSKEY signature validity period (hours):" values are set to less than 48 hours or more than 168 hours, this is a finding.'
  desc 'fix', 'Log on to the DNS server using the account designated as Administrator or DNS Administrator.

Press the Windows key + R and execute "dnsmgmt.msc".

On the opened DNS Manager snap-in from the left pane, expand the server name for the DNS server and then expand "Forward Lookup Zones".

From the expanded list, click to select the zone.

Right-click the zone and select DNSSEC >> Properties.

Select the "KSK" tab. For the "DNSKEY RRSET signature validity period (hours):" setting, configure to a value between 48 and 168 hours. 

Select the "ZSK" tab. For the "DNSKEY signature validity period (hours):" setting, configure to a value between 48 and 168 hours.'
  impact 0.5
  tag check_id: 'C-WDNS-22-000014_chk'
  tag severity: 'medium'
  tag gid: 'WDNS-22-000014'
  tag rid: 'WDNS-22-000014_rule'
  tag stig_id: 'WDNS-22-000014'
  tag gtitle: 'SRG-APP-000516-DNS-000078'
  tag fix_id: 'F-WDNS-22-000014_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
