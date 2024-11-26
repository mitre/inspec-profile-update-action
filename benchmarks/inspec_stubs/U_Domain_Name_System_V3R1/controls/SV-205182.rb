control 'SV-205182' do
  title 'The DNS implementation must protect the authenticity of communications sessions for zone transfers.'
  desc 'DNS is a fundamental network service that is prone to various attacks, such as cache poisoning and man-in-the middle attacks. 

If communication sessions are not provided appropriate validity protections, such as the employment of DNSSEC, the authenticity of the data cannot be guaranteed.'
  desc 'check', 'Review the DNS server implementation to confirm zone transfers are signing using transaction signing (TSIG) shared key or via SIG(0) asymmetric cryptography public keys.

If the DNS server does not ensure integrity of zone transfers by TSIG or SIG(0) signing, this is a finding.'
  desc 'fix', 'Configure the DNS server with transaction signing (TSIG) or SIG(0).'
  impact 0.5
  ref 'DPMS Target DNS'
  tag check_id: 'C-5449r392459_chk'
  tag severity: 'medium'
  tag gid: 'V-205182'
  tag rid: 'SV-205182r879636_rule'
  tag stig_id: 'SRG-APP-000219-DNS-000028'
  tag gtitle: 'SRG-APP-000219'
  tag fix_id: 'F-5449r392460_fix'
  tag 'documentable'
  tag legacy: ['SV-69071', 'V-54825']
  tag cci: ['CCI-001184']
  tag nist: ['SC-23']
end
