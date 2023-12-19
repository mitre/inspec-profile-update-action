control 'SV-215661' do
  title 'The validity period for the RRSIGs covering the DS RR for a zones delegated children must be no less than two days and no more than one week.'
  desc "The best way for a zone administrator to minimize the impact of a key compromise is by limiting the validity period of RRSIGs in the zone and in the parent zone. This strategy limits the time during which an attacker can take advantage of a compromised key to forge responses. An attacker that has compromised a ZSK can use that key only during the KSK's signature validity interval. An attacker that has compromised a KSK can use that key for only as long as the signature interval of the RRSIG covering the DS RR in the delegating parent. These validity periods should be short, which will require frequent re-signing.

To prevent the impact of a compromised KSK, a delegating parent should set the signature validity period for RRSIGs covering DS RRs in the range of a few days to 1 week. This re-signing does not require frequent rollover of the parent's ZSK, but scheduled ZSK rollover should still be performed at regular intervals."
  desc 'check', 'Note: This check is Not applicable for Windows 2012 DNS Servers that only host Active Directory integrated zones or for Windows 2012 DNS servers on a Classified network.

Log on to the DNS server using the Domain Admin or Enterprise Admin account or Local Administrator account.

Press Windows Key + R, execute dnsmgmt.msc.

On the opened DNS Manager snap-in from the left pane, expand the server name for the DNS server, and then expand Forward Lookup Zones.

From the expanded list, click to select the zone. 

View the validity period for the DS Resource Record. 

If the validity period for the DS Resource Record for the child domain is less than two days (48 hours) or more than one week (168 hours), this is a finding.'
  desc 'fix', 'Log on to the DNS server using the Domain Admin or Enterprise Admin account or Local Administrator account.

Press Windows Key + R, execute dnsmgmt.msc.

On the opened DNS Manager snap-in from the left pane, expand the server name for the DNS server, and then expand Forward Lookup Zones.

From the expanded list, click to select the zone. 

Right-click on the zone, choose DNSSEC->Properties.
 
On the ZSK tab, for DS signature validity period (hours), choose more than 48 and less than 168.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 2012 Server Domain Name System'
  tag check_id: 'C-16855r572188_chk'
  tag severity: 'medium'
  tag gid: 'V-215661'
  tag rid: 'SV-215661r561297_rule'
  tag stig_id: 'WDNS-CM-000001'
  tag gtitle: 'SRG-APP-000214-DNS-000079'
  tag fix_id: 'F-16853r572189_fix'
  tag 'documentable'
  tag legacy: ['SV-73005', 'V-58575']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
