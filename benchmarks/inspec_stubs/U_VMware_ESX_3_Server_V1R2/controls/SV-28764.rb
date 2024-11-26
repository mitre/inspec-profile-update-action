control 'SV-28764' do
  title 'If the system is using LDAP for authentication or account information, the system must use a FIPS 140-2 validated cryptographic module (operating in FIPS mode) for protecting the LDAP connection.'
  desc 'LDAP can be used to provide user authentication and account information, which are vital to system security. Cryptographic modules used by the system must be validated by the NIST CVMP as compliant with FIPS 140-2. Cryptography performed by modules not validated is viewed by NIST as providing no protection for the data.'
  desc 'check', 'Determine if the system uses NSS LDAP. If it does not, this is not applicable.

Determine if the system uses a FIPS 140-2 validated cryptographic module (operating in FIPS mode) for protecting the NSS LDAP connection. If it does not, this is a finding.'
  desc 'fix', 'Configure the system to use a FIPS 140-2 validated cryptographic module (operating in FIPS mode) for protecting the NSS LDAP connection.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-29155r1_chk'
  tag severity: 'medium'
  tag gid: 'V-23828'
  tag rid: 'SV-28764r1_rule'
  tag stig_id: 'GEN007970'
  tag gtitle: 'GEN007970'
  tag fix_id: 'F-26166r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'DCNR-1'
  tag cci: ['CCI-001145']
  tag nist: ['SC-13 (1)']
end
