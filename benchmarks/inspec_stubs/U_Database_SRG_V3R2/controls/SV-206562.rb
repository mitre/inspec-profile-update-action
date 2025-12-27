control 'SV-206562' do
  title 'The DBMS must use NIST FIPS 140-2 validated cryptographic modules for cryptographic operations.'
  desc 'Use of weak or not validated cryptographic algorithms undermines the purposes of utilizing encryption and digital signatures to protect data.  Weak algorithms can be easily broken and not validated cryptographic modules may not implement algorithms correctly. Unapproved cryptographic modules or algorithms should not be relied on for authentication, confidentiality or integrity. Weak cryptography could allow an attacker to gain access to and modify data stored in the database as well as the administration settings of the DBMS.

Applications, including DBMSs, utilizing cryptography are required to use approved NIST FIPS 140-2 validated cryptographic modules that meet the requirements of applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.  

The security functions validated as part of FIPS 140-2 for cryptographic modules are described in FIPS 140-2 Annex A.

NSA Type-X (where X=1, 2, 3, 4) products are NSA-certified, hardware-based encryption modules.'
  desc 'check', 'Review DBMS configuration to verify it is using NIST FIPS 140-2 validated cryptographic modules for cryptographic operations.

If NIST FIPS 140-2 validated modules are not being used for all cryptographic operations, this is a finding.'
  desc 'fix', 'Utilize NIST FIPS 140-2 validated cryptographic modules for all cryptographic operations.'
  impact 0.7
  ref 'DPMS Target Database Generic'
  tag check_id: 'C-6822r291354_chk'
  tag severity: 'high'
  tag gid: 'V-206562'
  tag rid: 'SV-206562r810840_rule'
  tag stig_id: 'SRG-APP-000179-DB-000114'
  tag gtitle: 'SRG-APP-000179'
  tag fix_id: 'F-6822r291355_fix'
  tag 'documentable'
  tag legacy: ['SV-42817', 'V-32480']
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
