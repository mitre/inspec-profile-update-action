control 'SV-240925' do
  title 'The application server must implement NSA-approved cryptography to protect classified information in accordance with applicable federal laws, Executive Orders, directives, policies, regulations, and standards.'
  desc 'Cryptography is only as strong as the encryption modules/algorithms employed to encrypt the data. Use of weak or untested encryption algorithms undermines the purposes of utilizing encryption to protect data.

NSA has developed Type 1 algorithms for protecting classified information. The Committee on National Security Systems (CNSS) National Information Assurance Glossary (CNSS Instruction No. 4009) defines Type 1 products as:

"Cryptographic equipment, assembly or component classified or certified by NSA for encrypting and decrypting classified and sensitive national security information when appropriately keyed. Developed using established NSA business processes and containing NSA-approved algorithms 
are used to protect systems requiring the most stringent protection mechanisms." 

NSA-approved cryptography is required to be used for classified information system processing.

The application server must utilize NSA-approved encryption modules when protecting classified data. This means using AES and other approved encryption modules.'
  desc 'check', 'Review application server documentation to verify that the application server is using NSA-approved cryptography to protect classified data and applications resident on the device.

If the application server is not using NSA-approved cryptography for classified data and applications, this is a finding.'
  desc 'fix', 'Configure the application server to utilize NSA-approved cryptography to protect classified information.'
  impact 0.5
  ref 'DPMS Target Application Server'
  tag check_id: 'C-44158r675811_chk'
  tag severity: 'medium'
  tag gid: 'V-240925'
  tag rid: 'SV-240925r879944_rule'
  tag stig_id: 'SRG-APP-000416-AS-000140'
  tag gtitle: 'SRG-APP-000416'
  tag fix_id: 'F-44117r675812_fix'
  tag 'documentable'
  tag legacy: ['SV-71817', 'V-57541']
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
