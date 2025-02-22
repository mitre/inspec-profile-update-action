control 'SV-205184' do
  title 'The DNS implementation must protect the authenticity of communications sessions for queries.'
  desc 'The underlying feature in the major threat associated with DNS query/response (i.e., forged response or response failure) is the integrity of DNS data returned in the response. An integral part of integrity verification is to ensure that valid data has originated from the right source. DNSSEC is required for securing the DNS query/response transaction by providing data origin authentication and data integrity verification through signature verification and the chain of trust.'
  desc 'check', 'Review the DNS server configuration to ensure all zones are configured to provide resolvers with verification of query response integrity via DNSSEC.

If the DNS Server configuration is not configured to provide resolvers with verification of query response integrity via the implementation of DNSSEC, this is a finding.'
  desc 'fix', 'Configure the DNS server to provide resolvers with verification of query response integrity via DNSSEC.'
  impact 0.5
  ref 'DPMS Target DNS'
  tag check_id: 'C-5451r392465_chk'
  tag severity: 'medium'
  tag gid: 'V-205184'
  tag rid: 'SV-205184r879636_rule'
  tag stig_id: 'SRG-APP-000219-DNS-000030'
  tag gtitle: 'SRG-APP-000219'
  tag fix_id: 'F-5451r392466_fix'
  tag 'documentable'
  tag legacy: ['SV-69075', 'V-54829']
  tag cci: ['CCI-001184']
  tag nist: ['SC-23']
end
