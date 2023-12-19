control 'SV-207579' do
  title 'The BIND 9.x server validity period for the RRSIGs covering the DS RR for zones delegated children must be no less than two days and no more than one week.'
  desc "The best way for a zone administrator to minimize the impact of a key compromise is by limiting the validity period of RRSIGs in the zone and in the parent zone. This strategy limits the time during which an attacker can take advantage of a compromised key to forge responses. An attacker that has compromised a ZSK can use that key only during the KSK's signature validity interval. An attacker that has compromised a KSK can use that key for only as long as the signature interval of the RRSIG covering the DS RR in the delegating parent. These validity periods should be short, which will require frequent re-signing.

To prevent the impact of a compromised KSK, a delegating parent should set the signature validity period for RRSIGs covering DS RRs in the range of a few days to 1 week. This re-signing does not require frequent rollover of the parent's ZSK, but scheduled ZSK rollover should still be performed at regular intervals."
  desc 'check', 'If the server is in a classified network, this is Not Applicable.
Note: This requirement does not validate the sig-validity-interval. This requirement ensures the signature validity period (i.e., the time from the signature’s inception until the signature’s expiration). It is recommended to ensure the Start of Authority (SOA) expire period (how long a secondary will still treat its copy of the zone data as valid if it cannot contact the primary.) is configured to ensure the SOA does not expire during the period of signature inception and signature expiration.

With the assistance of the DNS Administrator, identify the RRSIGs that cover the DS resource records for each child zone.

Each record will list an expiration and inception date, the difference of which will provide the validity period.

The dates are listed in the following format:

YYYYMMDDHHMMSS

For each RRSIG identified, verify that the validity period is no less than two days and is no longer than seven days.

If the validity period is outside of the specified range, this is a finding.'
  desc 'fix', 'Resign the child zone files and have the zone administrator provide updated DS resource records for the child zone.'
  impact 0.5
  ref 'DPMS Target BIND 9.x'
  tag check_id: 'C-7834r283791_chk'
  tag severity: 'medium'
  tag gid: 'V-207579'
  tag rid: 'SV-207579r612253_rule'
  tag stig_id: 'BIND-9X-001311'
  tag gtitle: 'SRG-APP-000214-DNS-000079'
  tag fix_id: 'F-7834r283792_fix'
  tag 'documentable'
  tag legacy: ['SV-87099', 'V-72475']
  tag cci: ['CCI-001179']
  tag nist: ['SC-20 b']
end
