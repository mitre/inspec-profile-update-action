control 'SV-205178' do
  title 'The validity period for the RRSIGs covering the DS RR for a zones delegated children must be no less than two days and no more than one week.'
  desc "The best way for a zone administrator to minimize the impact of a key compromise is by limiting the validity period of RRSIGs in the zone and in the parent zone. This strategy limits the time during which an attacker can take advantage of a compromised key to forge responses. An attacker that has compromised a ZSK can use that key only during the KSK's signature validity interval. An attacker that has compromised a KSK can use that key for only as long as the signature interval of the RRSIG covering the DS RR in the delegating parent. These validity periods should be short, which will require frequent re-signing.

To prevent the impact of a compromised KSK, a delegating parent should set the signature validity period for RRSIGs covering DS RRs in the range of a few days to 1 week. This re-signing does not require frequent rollover of the parent's ZSK, but scheduled ZSK rollover should still be performed at regular intervals."
  desc 'check', "Review the DNS configuration files. Ensure the validity period for RRSIGs for all zones' delegated children has been explicitly configured and is configured for a range of no less than two days and no more than one week.

If the validity period for the RRSIGs for all zones' delegated children is less than two days or greater than one week, this is a finding."
  desc 'fix', "Configure RRSIGs for all zones' delegated children to be greater than two days and less than one week."
  impact 0.5
  ref 'DPMS Target DNS'
  tag check_id: 'C-5445r392450_chk'
  tag severity: 'medium'
  tag gid: 'V-205178'
  tag rid: 'SV-205178r879634_rule'
  tag stig_id: 'SRG-APP-000214-DNS-000079'
  tag gtitle: 'SRG-APP-000214'
  tag fix_id: 'F-5445r392451_fix'
  tag 'documentable'
  tag legacy: ['SV-69065', 'V-54819']
  tag cci: ['CCI-001179']
  tag nist: ['SC-20 b']
end
