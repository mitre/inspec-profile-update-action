control 'SV-204818' do
  title 'The application server must employ approved cryptographic mechanisms to prevent unauthorized disclosure of information and/or detect changes to information during transmission.'
  desc 'Preventing the disclosure or modification of transmitted information requires that application servers take measures to employ approved cryptography in order to protect the information during transmission over the network. This is usually achieved through the use of Transport Layer Security (TLS), SSL VPN, or IPSec tunnel.

If data in transit is unencrypted, it is vulnerable to disclosure and modification. If approved cryptographic algorithms are not used, encryption strength cannot be assured.

TLS must be enabled and non-FIPS-approved SSL versions must be disabled.  NIST SP 800-52 specifies the preferred configurations for government systems.'
  desc 'check', 'Review application server documentation and configuration to determine if the application server employs approved cryptographic mechanisms to prevent unauthorized disclosure of information and/or detect changes to information during transmission.

If the application server does not employ approved cryptographic mechanisms, this is a finding.'
  desc 'fix', 'Configure the application server to use AES 128 or AES 256 encryption for data in transit.'
  impact 0.5
  ref 'DPMS Target Application Server'
  tag check_id: 'C-4938r283095_chk'
  tag severity: 'medium'
  tag gid: 'V-204818'
  tag rid: 'SV-204818r508029_rule'
  tag stig_id: 'SRG-APP-000440-AS-000167'
  tag gtitle: 'SRG-APP-000440'
  tag fix_id: 'F-4938r283096_fix'
  tag 'documentable'
  tag legacy: ['SV-71811', 'V-57535']
  tag cci: ['CCI-002421']
  tag nist: ['SC-8 (1)']
end
