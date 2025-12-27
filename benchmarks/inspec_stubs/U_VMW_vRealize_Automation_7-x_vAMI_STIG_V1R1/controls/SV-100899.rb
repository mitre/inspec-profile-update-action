control 'SV-100899' do
  title 'The vAMI must implement NSA-approved cryptography to protect classified information in accordance with applicable federal laws, Executive Orders, directives, policies, regulations, and standards.'
  desc "Cryptography is only as strong as the encryption modules/algorithms employed to encrypt the data. Use of weak or untested encryption algorithms undermines the purposes of utilizing encryption to protect data. NSA has developed Type 1 algorithms for protecting classified information. The Committee on National Security Systems (CNSS) National Information Assurance Glossary (CNSS Instruction No. 4009) defines Type 1 products as: 'Cryptographic equipment, assembly or component classified or certified by NSA for encrypting and decrypting classified and sensitive national security information when appropriately keyed. Developed using established NSA business processes and containing NSA-approved algorithms are used to protect systems requiring the most stringent protection mechanisms.' NSA-approved cryptography is required to be used for classified information system processing. The application server must utilize NSA-approved encryption modules when protecting classified data. This means using AES and other approved encryption modules."
  desc 'check', %q(At the command prompt, execute the following command:

grep 'ssl.cipher-list' /opt/vmware/etc/lighttpd/lighttpd.conf

If the value of "ssl.cipher-list" is not "FIPS: +3DES:!aNULL", this is a finding.)
  desc 'fix', %q(Navigate to and open /opt/vmware/etc/lighttpd/lighttpd.conf.

Configure the lighttpd.conf file with the following value: 'ssl.cipher-list = "FIPS: +3DES:!aNULL"')
  impact 0.5
  ref 'DPMS Target vRealize Automation 7.x VAMI'
  tag check_id: 'C-89941r1_chk'
  tag severity: 'medium'
  tag gid: 'V-90249'
  tag rid: 'SV-100899r1_rule'
  tag stig_id: 'VRAU-VA-000530'
  tag gtitle: 'SRG-APP-000416-AS-000140'
  tag fix_id: 'F-96991r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
