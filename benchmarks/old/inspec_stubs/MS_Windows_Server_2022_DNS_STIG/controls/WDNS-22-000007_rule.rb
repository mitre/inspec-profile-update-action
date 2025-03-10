control 'WDNS-22-000007_rule' do
  title "The validity period for the Resource Record Signatures (RRSIGs) covering the Delegation Signer (DS) Resource Record (RR) for a zone's delegated children must be no less than two days and no more than one week."
  desc "The best way for a zone administrator to minimize the impact of a key compromise is by limiting the validity period of RRSIGs in the zone and the parent zone. This strategy limits the time during which an attacker can take advantage of a compromised key to forge responses. An attacker that has compromised a zone signing key (ZSK) can use that key only during the key signing key's (KSK's) signature validity interval. An attacker that has compromised a KSK can use that key for only as long as the signature interval of the RRSIG covering the DS RR in the delegating parent. These validity periods should be short, which will require frequent re-signing.

To prevent the impact of a compromised KSK, a delegating parent should set the signature validity period for RRSIGs covering DS RRs in the range of a few days to one week. This re-signing does not require frequent rollover of the parent's ZSK, but scheduled ZSK rollover should still be performed at regular intervals."
  desc 'check', 'Note: This check is not applicable for Windows 2022 DNS Servers that host only Active Directory-integrated zones or for Windows 2022 DNS Servers on a classified network.

Log on to the DNS server using the Domain Admin or Enterprise Admin account or Local Administrator account.

Press the Windows key + R and execute "dnsmgmt.msc".

On the opened DNS Manager snap-in from the left pane, expand the server name for the DNS server and then expand "Forward Lookup Zones".

From the expanded list, click to select the zone. 

View the validity period for the DS RR. 

If the validity period for the DS RR for the child domain is less than two days (48 hours) or more than one week (168 hours), this is a finding.'
  desc 'fix', 'Log on to the DNS server using the Domain Admin or Enterprise Admin account or Local Administrator account.

Press the Windows key + R and execute "dnsmgmt.msc".

On the opened DNS Manager snap-in from the left pane, expand the server name for the DNS server and then expand "Forward Lookup Zones".

From the expanded list, click to select the zone. 

Right-click on the zone and choose DNSSEC >> Properties.
 
On the ZSK tab, for DS signature validity period (hours), choose more than 48 and less than 168.'
  impact 0.5
  tag check_id: 'C-WDNS-22-000007_chk'
  tag severity: 'medium'
  tag gid: 'WDNS-22-000007'
  tag rid: 'WDNS-22-000007_rule'
  tag stig_id: 'WDNS-22-000007'
  tag gtitle: 'SRG-APP-000214-DNS-000079'
  tag fix_id: 'F-WDNS-22-000007_fix'
  tag 'documentable'
  tag cci: ['CCI-001179']
  tag nist: ['SC-20 b']
end
