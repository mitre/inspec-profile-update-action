control 'SV-205187' do
  title 'The DNS server implementation must protect the confidentiality and integrity of secret/private cryptographic keys at rest and the integrity of DNS information at rest.'
  desc 'Information at rest refers to the state of information when it is located on a secondary storage device within an organizational information system. Mobile devices, laptops, desktops, and storage devices can be either lost or stolen, and the contents of their data storage (e.g., hard drives and non-volatile memory) can be read, copied, or altered. Applications and application users generate information throughout the course of their application use.

The DNS server must protect the confidentiality and integrity of shared keys (for TSIG) and private keys (for SIG(0)) and must protect the integrity of DNS information. There is no need to protect the confidentiality of DNS information because it is accessible by all devices that can contact the server.'
  desc 'check', 'Review the DNS server implementation configuration to determine if the DNS server protects the confidentiality and integrity of secret/private cryptographic keys at rest and the integrity of DNS information at rest. If the DNS server does not properly protect confidentiality and integrity, this is a finding.'
  desc 'fix', 'Configure the DNS server to protect the confidentiality and integrity of secret/private cryptographic keys at rest and the integrity of DNS information at rest.'
  impact 0.5
  ref 'DPMS Target DNS'
  tag check_id: 'C-5454r392474_chk'
  tag severity: 'medium'
  tag gid: 'V-205187'
  tag rid: 'SV-205187r879642_rule'
  tag stig_id: 'SRG-APP-000231-DNS-000033'
  tag gtitle: 'SRG-APP-000231'
  tag fix_id: 'F-5454r392475_fix'
  tag 'documentable'
  tag legacy: ['SV-69081', 'V-54835']
  tag cci: ['CCI-001199']
  tag nist: ['SC-28']
end
