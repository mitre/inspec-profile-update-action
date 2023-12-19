control 'SV-207482' do
  title 'The VMM must electronically verify Personal Identity Verification (PIV) credentials.'
  desc 'The use of PIV credentials facilitates standardization and reduces the risk of unauthorized access.

DoD has mandated the use of the CAC to support identity management and personal authentication for systems covered under Homeland Security Presidential Directive (HSPD) 12 and as a primary component of layered protection for national security systems.'
  desc 'check', 'Verify the VMM electronically verifies Personal Identity Verification (PIV) credentials.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to electronically verify Personal Identity Verification (PIV) credentials.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7739r365850_chk'
  tag severity: 'medium'
  tag gid: 'V-207482'
  tag rid: 'SV-207482r854656_rule'
  tag stig_id: 'SRG-OS-000377-VMM-001530'
  tag gtitle: 'SRG-OS-000377'
  tag fix_id: 'F-7739r365851_fix'
  tag 'documentable'
  tag legacy: ['V-57165', 'SV-71425']
  tag cci: ['CCI-001954']
  tag nist: ['IA-2 (12)']
end
