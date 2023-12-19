control 'SV-240860' do
  title 'tc Server HORIZON must use NSA Suite A cryptography when encrypting data that must be compartmentalized.'
  desc 'Cryptography is only as strong as the encryption modules/algorithms employed to encrypt the data. 

Use of weak or untested encryption algorithms undermines the purposes of utilizing encryption to protect data. 

NSA has developed Type 1 algorithms for protecting classified information. The Committee on National Security Systems (CNSS) National Information Assurance Glossary (CNSS Instruction No. 4009) defines Type 1 products as:

"Cryptographic equipment, assembly or component classified or certified by NSA for encrypting and decrypting classified and sensitive national security information when appropriately keyed. Developed using established NSA business processes and containing NSA-approved algorithms are used to protect systems requiring the most stringent protection mechanisms."

Although persons may have a security clearance, they may not have a "need-to-know" and are required to be separated from the information in question. The web server must employ NSA-approved cryptography to protect classified information from those individuals who have no "need-to-know" or when encryption of compartmentalized data is required by data classification.'
  desc 'check', 'If the system is not implemented to process compartmentalized information, this requirement is Not Applicable.

At the command prompt, execute the following command:

grep bio-ssl.cipher.list /opt/vmware/horizon/workspace/conf/catalina.properties

If the value of "bio-ssl.cipher.list" does not match the list of NSA Suite A ciphers or is missing, this is a finding.'
  desc 'fix', 'Navigate to and open /opt/vmware/horizon/workspace/conf/catalina.properties.

Navigate to the "bio-ssl.cipher.list" setting.

Configure "bio-ssl.cipher.list" with a list of NSA Suite A ciphers.'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x tc Server'
  tag check_id: 'C-44093r674461_chk'
  tag severity: 'medium'
  tag gid: 'V-240860'
  tag rid: 'SV-240860r674462_rule'
  tag stig_id: 'VRAU-TC-000820'
  tag gtitle: 'SRG-APP-000416-WSR-000118'
  tag fix_id: 'F-44052r674323_fix'
  tag 'documentable'
  tag legacy: ['SV-100799', 'V-90149']
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
