control 'SV-213322' do
  title 'The McAfee Application Control Options Advanced Threat Defense (ATD) settings, if being used, must be confined to the organizations enclave.'
  desc 'Data will be leaving the endpoint to be analyzed by the ATD. Because data could feasibly be intercepted en route, risk of outside threats is minimized by ensuring the ATD is in the same enclave as the endpoints.'
  desc 'check', "If an ATD server is not being used in the environment, this is Not Applicable.

Consult with the ISSO/ISSM to review the written policy to ensure the usage of an ATD is documented.

If the usage of an ATD is not documented in the written policy, this is a finding.

Determine the location of the ATD being used by the organization and verify the ATD is confined to the organization's enclave.

If the location of the ATD being used by the organization cannot be determined and the ATD is not confined to the organization's enclave, this is a finding."
  desc 'fix', "Relocate or reinstall the ATD being used by the organization to be confined to the organization's enclave."
  impact 0.5
  ref 'DPMS Target McAfee Application Control 8.x'
  tag check_id: 'C-14550r309063_chk'
  tag severity: 'medium'
  tag gid: 'V-213322'
  tag rid: 'SV-213322r506897_rule'
  tag stig_id: 'MCAC-PO-000106'
  tag gtitle: 'SRG-APP-000276'
  tag fix_id: 'F-14548r309064_fix'
  tag 'documentable'
  tag legacy: ['SV-88875', 'V-74201']
  tag cci: ['CCI-001240']
  tag nist: ['SI-3 b']
end
