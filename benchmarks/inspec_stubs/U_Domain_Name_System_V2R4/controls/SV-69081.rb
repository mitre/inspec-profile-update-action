control 'SV-69081' do
  title 'The DNS server implementation must protect the confidentiality and integrity of secret/private cryptographic keys at rest and the integrity of DNS information at rest.'
  desc 'Information at rest refers to the state of information when it is located on a secondary storage device within an organizational information system. Mobile devices, laptops, desktops, and storage devices can be either lost or stolen, and the contents of their data storage (e.g., hard drives and non-volatile memory) can be read, copied, or altered. Applications and application users generate information throughout the course of their application use.

The DNS server must protect the confidentiality and integrity of shared keys (for TSIG) and private keys (for SIG(0)) and must protect the integrity of DNS information. There is no need to protect the confidentiality of DNS information because it is accessible by all devices that can contact the server.'
  desc 'check', 'Review the DNS server implementation configuration to determine if the DNS server protects the confidentiality and integrity of secret/private cryptographic keys at rest and the integrity of DNS information at rest. If the DNS server does not properly protect confidentiality and integrity, this is a finding.'
  desc 'fix', 'Configure the DNS server to protect the confidentiality and integrity of secret/private cryptographic keys at rest and the integrity of DNS information at rest.'
  impact 0.5
  ref 'DPMS Target SRG-APP-DNS'
  tag check_id: 'C-55457r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54835'
  tag rid: 'SV-69081r1_rule'
  tag stig_id: 'SRG-APP-000231-DNS-000033'
  tag gtitle: 'SRG-APP-000231-DNS-000033'
  tag fix_id: 'F-59693r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001199']
  tag nist: ['SC-28']
end
