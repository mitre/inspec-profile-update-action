control 'SV-69071' do
  title 'The DNS implementation must protect the authenticity of communications sessions for zone transfers.'
  desc 'DNS is a fundamental network service that is prone to various attacks, such as cache poisoning and man-in-the middle attacks. 

If communication sessions are not provided appropriate validity protections, such as the employment of DNSSEC, the authenticity of the data cannot be guaranteed.'
  desc 'check', 'Review the DNS server implementation to confirm zone transfers are signing using transaction signing (TSIG) shared key or via SIG(0) asymmetric cryptography public keys.

If the DNS server does not ensure integrity of zone transfers by TSIG or SIG(0) signing, this is a finding.'
  desc 'fix', 'Configure the DNS server with transaction signing (TSIG) or SIG(0).'
  impact 0.5
  ref 'DPMS Target SRG-APP-DNS'
  tag check_id: 'C-55447r2_chk'
  tag severity: 'medium'
  tag gid: 'V-54825'
  tag rid: 'SV-69071r1_rule'
  tag stig_id: 'SRG-APP-000219-DNS-000028'
  tag gtitle: 'SRG-APP-000219-DNS-000028'
  tag fix_id: 'F-59683r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001184']
  tag nist: ['SC-23']
end
