control 'SV-207339' do
  title 'The VMM must automatically remove or disable local temporary user accounts after 72 hours.'
  desc 'If temporary user accounts remain active when no longer needed or for an excessive period, these accounts may be used to gain unauthorized access. To mitigate this risk, automated termination of all temporary accounts must be set upon account creation. 

Temporary accounts are established as part of normal account activation procedures when there is a need for short-term accounts without the demand for immediacy in account activation. 

If temporary accounts are used, the VMM must be configured to automatically terminate these types of accounts after a DoD-defined time period of 72 hours.

To address access requirements, many VMMs may be integrated with enterprise level authentication/access mechanisms that meet or exceed access control policy requirements.'
  desc 'check', 'Verify the VMM automatically removes or disables local temporary user accounts after 72 hours.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to automatically remove or disable local temporary user accounts after 72 hours.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7596r365427_chk'
  tag severity: 'medium'
  tag gid: 'V-207339'
  tag rid: 'SV-207339r378481_rule'
  tag stig_id: 'SRG-OS-000002-VMM-000020'
  tag gtitle: 'SRG-OS-000002'
  tag fix_id: 'F-7596r365428_fix'
  tag 'documentable'
  tag legacy: ['SV-71079', 'V-56819']
  tag cci: ['CCI-000016']
  tag nist: ['AC-2 (2)']
end
