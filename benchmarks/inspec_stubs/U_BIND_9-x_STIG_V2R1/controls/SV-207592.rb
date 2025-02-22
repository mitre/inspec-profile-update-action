control 'SV-207592' do
  title 'A BIND 9.x server validity period for the RRSIGs covering a zones DNSKEY RRSet must be no less than two days and no more than one week.'
  desc "The best way for a zone administrator to minimize the impact of a key compromise is by limiting the validity period of RRSIGs in the zone and in the parent zone. This strategy limits the time during which an attacker can take advantage of a compromised key to forge responses. An attacker that has compromised a ZSK can use that key only during the KSK's signature validity interval. An attacker that has compromised a KSK can use that key for only as long as the signature interval of the RRSIG covering the DS RR in the delegating parent. These validity periods should be short, which will require frequent re-signing."
  desc 'check', 'If the server is in a classified network, this is Not Applicable.

With the assistance of the DNS Administrator, identify the RRSIGs that cover the DNSKEY resource record set for each zone.

Each record will list an expiration and inception date, the difference of which will provide the validity period.

The dates are listed in the following format:

YYYYMMDDHHMMSS

For each RRSIG identified, verify that the validity period is no less than two days and is no longer than seven days.

If the validity period is outside of the specified range, this is a finding.'
  desc 'fix', 'Resign each zone that is outside of the validity period.

Restart the BIND 9.x process.'
  impact 0.5
  ref 'DPMS Target BIND 9.x'
  tag check_id: 'C-7847r283830_chk'
  tag severity: 'medium'
  tag gid: 'V-207592'
  tag rid: 'SV-207592r612253_rule'
  tag stig_id: 'BIND-9X-001600'
  tag gtitle: 'SRG-APP-000516-DNS-000078'
  tag fix_id: 'F-7847r283831_fix'
  tag 'documentable'
  tag legacy: ['SV-87125', 'V-72501']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
