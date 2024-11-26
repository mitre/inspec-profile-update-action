control 'SV-251245' do
  title 'Database contents must be protected from unauthorized and unintended information transfer by enforcement of a data-transfer policy.'
  desc 'Security functions are the hardware, software, and/or firmware of the information system responsible for enforcing the system security policy and supporting the isolation of code and data on which the protection is based.'
  desc 'check', 'Review the procedures for the refreshing of development/test data from production.

Review any scripts or code that exists for the movement of production data to development/test systems, or to any other location or for any other purpose.

Verify that copies of production data are not left in unprotected locations. 

If the code that exists for data movement does not comply with the organization-defined data transfer policy and/or fails to remove any copies of production data from unprotected locations, this is a finding.'
  desc 'fix', 'Modify any code used for moving data from production to development/test systems to comply with the organization-defined data transfer policy, and to ensure copies of production data are not left in unsecured locations.'
  impact 0.5
  ref 'DPMS Target Redis Enterprise 6.x'
  tag check_id: 'C-54680r804923_chk'
  tag severity: 'medium'
  tag gid: 'V-251245'
  tag rid: 'SV-251245r804925_rule'
  tag stig_id: 'RD6X-00-011300'
  tag gtitle: 'SRG-APP-000243-DB-000128'
  tag fix_id: 'F-54634r804924_fix'
  tag 'documentable'
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']
end
