control 'SV-205228' do
  title 'The validity period for the RRSIGs covering a zones DNSKEY RRSet must be no less than two days and no more than one week.'
  desc "The best way for a zone administrator to minimize the impact of a key compromise is by limiting the validity period of RRSIGs in the zone and in the parent zone. This strategy limits the time during which an attacker can take advantage of a compromised key to forge responses. An attacker that has compromised a ZSK can use that key only during the KSK's signature validity interval. An attacker that has compromised a KSK can use that key for only as long as the signature interval of the RRSIG covering the DS RR in the delegating parent. These validity periods should be short, which will require frequent re-signing.

To minimize the impact of a compromised ZSK, a zone administrator should set a signature validity period of 1 week for RRSIGs covering the DNSKEY RRSet in the zone (the RRSet that contains the ZSK and KSK for the zone). The DNSKEY RRSet can be re-signed without performing a ZSK rollover, but scheduled ZSK rollover should still be performed at regular intervals."
  desc 'check', "Review the DNS configuration files. Ensure the validity period for RRSIGs has been explicitly configured and is configured for a range of no less than two days and no more than one week.

If the validity period for the RRSIGs covering a zone's DNSKEY RRSet is less than two days or greater than one week, this is a finding."
  desc 'fix', "Configure RRSIGs covering each zone's DNSKEY RRSet to be greater than two days and less than one week."
  impact 0.5
  ref 'DPMS Target DNS'
  tag check_id: 'C-5495r392597_chk'
  tag severity: 'medium'
  tag gid: 'V-205228'
  tag rid: 'SV-205228r879887_rule'
  tag stig_id: 'SRG-APP-000516-DNS-000078'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-5495r392598_fix'
  tag 'documentable'
  tag legacy: ['SV-69165', 'V-54919']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
