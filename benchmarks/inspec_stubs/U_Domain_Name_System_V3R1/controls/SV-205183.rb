control 'SV-205183' do
  title 'The DNS implementation must protect the authenticity of communications sessions for dynamic updates.'
  desc 'DNS is a fundamental network service that is prone to various attacks, such as cache poisoning and man-in-the middle attacks. If communication sessions are not provided appropriate validity protections, such as the employment of DNSSEC, the authenticity of the data cannot be guaranteed.'
  desc 'check', 'Review the DNS server configuration to determine if communication sessions for dynamic updates are provided authenticity protection. 

If communications sessions do not employ authenticity protections, this is a finding.'
  desc 'fix', 'Configure the DNS server to employ mechanisms to protect the authenticity of communications sessions for dynamic updates.'
  impact 0.5
  ref 'DPMS Target DNS'
  tag check_id: 'C-5450r392462_chk'
  tag severity: 'medium'
  tag gid: 'V-205183'
  tag rid: 'SV-205183r879636_rule'
  tag stig_id: 'SRG-APP-000219-DNS-000029'
  tag gtitle: 'SRG-APP-000219'
  tag fix_id: 'F-5450r392463_fix'
  tag 'documentable'
  tag legacy: ['SV-69073', 'V-54827']
  tag cci: ['CCI-001184']
  tag nist: ['SC-23']
end
