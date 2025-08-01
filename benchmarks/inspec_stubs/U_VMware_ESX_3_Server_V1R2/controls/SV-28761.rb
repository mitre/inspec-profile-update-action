control 'SV-28761' do
  title 'The system must use a FIPS 140-2 validated cryptographic module (operating in FIPS mode) for generating system password hashes.'
  desc 'Cryptographic modules used by the system must be validated by the NIST CVMP as compliant with FIPS 140-2. Cryptography performed by modules not validated is viewed by NIST as providing no protection for the data.'
  desc 'check', 'Determine if the system uses a FIPS 140-2 validated cryptographic module (operating in FIPS mode) for generating system password hashes. The NIST CVMP web site provides a list of validated modules and the required security policies for the compliant use of such modules. Verify the module is on this list and configured in accordance with the validated security policy.

If the system does not use a FIPS 140-2 validated cryptographic module (operating in FIPS mode) for generating system password hashes, this is a finding.'
  desc 'fix', 'Configure the system to use a FIPS 140-2 validated cryptographic module (operating in FIPS mode) for generating system password hashes.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-29148r1_chk'
  tag severity: 'medium'
  tag gid: 'V-23825'
  tag rid: 'SV-28761r1_rule'
  tag stig_id: 'GEN000588'
  tag gtitle: 'GEN000588'
  tag fix_id: 'F-26159r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'DCNR-1'
  tag cci: ['CCI-001145']
  tag nist: ['SC-13 (1)']
end
