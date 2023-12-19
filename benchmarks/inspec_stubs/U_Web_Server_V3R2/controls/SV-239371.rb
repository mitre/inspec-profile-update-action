control 'SV-239371' do
  title 'The web server must implement required cryptographic protections using cryptographic modules complying with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance when encrypting data that must be compartmentalized.'
  desc 'Cryptography is only as strong as the encryption modules/algorithms employed to encrypt the data. 

Use of weak or untested encryption algorithms undermines the purposes of utilizing encryption to protect data. 

NSA has developed Type 1 algorithms for protecting classified information. The Committee on National Security Systems (CNSS) National Information Assurance Glossary (CNSS Instruction No. 4009) defines Type 1 products as:

"Cryptographic equipment, assembly or component classified or certified by NSA for encrypting and decrypting classified and sensitive national security information when appropriately keyed. Developed using established NSA business processes and containing NSA-approved algorithms are used to protect systems requiring the most stringent protection mechanisms."

Although persons may have a security clearance, they may not have a "need-to-know" and are required to be separated from the information in question. The web server must employ NSA-approved cryptography to protect classified information from those individuals who have no "need-to-know" or when encryption of compartmentalized data is required by data classification.'
  desc 'check', 'Review policy documents to identify data that is compartmentalized (i.e. classified, sensitive, need-to-know, etc.) and requires cryptographic protection.

Review the web server documentation and deployed configuration to identify the encryption modules utilized to protect the compartmentalized data.

If the encryption modules used to protect the compartmentalized data are not compliant with the data, this is a finding.'
  desc 'fix', 'Configure the web server to utilize cryptography when protecting compartmentalized data.'
  impact 0.5
  ref 'DPMS Target Web Server'
  tag check_id: 'C-42604r659514_chk'
  tag severity: 'medium'
  tag gid: 'V-239371'
  tag rid: 'SV-239371r879944_rule'
  tag stig_id: 'SRG-APP-000416-WSR-000118'
  tag gtitle: 'SRG-APP-000416'
  tag fix_id: 'F-42563r659515_fix'
  tag 'documentable'
  tag legacy: ['SV-70271', 'V-56017']
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
