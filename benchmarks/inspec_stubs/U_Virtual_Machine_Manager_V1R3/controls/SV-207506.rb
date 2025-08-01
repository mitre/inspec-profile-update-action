control 'SV-207506' do
  title 'The VMM must verify correct operation of all security functions.'
  desc 'Without verification of the security functions, security functions may not operate correctly and the failure may go unnoticed. Security function is defined as the hardware, software, and/or firmware of the VMM responsible for enforcing the system security policy and supporting the isolation of code and data on which the protection is based. Security functionality includes, but is not limited to, establishing system accounts, configuring access authorizations (i.e., permissions, privileges), setting events to be audited, and setting intrusion detection parameters.'
  desc 'check', 'Verify the VMM verifies correct operation of all security functions.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to verify correct operation of all security functions.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7763r365922_chk'
  tag severity: 'medium'
  tag gid: 'V-207506'
  tag rid: 'SV-207506r854680_rule'
  tag stig_id: 'SRG-OS-000445-VMM-001780'
  tag gtitle: 'SRG-OS-000445'
  tag fix_id: 'F-7763r365923_fix'
  tag 'documentable'
  tag legacy: ['SV-71573', 'V-57313']
  tag cci: ['CCI-002696']
  tag nist: ['SI-6 a']
end
