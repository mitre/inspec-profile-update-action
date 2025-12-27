control 'SV-207481' do
  title 'The VMM must accept Personal Identity Verification (PIV) credentials.'
  desc 'The use of PIV credentials facilitates standardization and reduces the risk of unauthorized access.

DoD has mandated the use of the CAC to support identity management and personal authentication for systems covered under Homeland Security Presidential Directive (HSPD) 12 and as a primary component of layered protection for national security systems.'
  desc 'check', 'Verify the VMM accepts Personal Identity Verification (PIV) credentials.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to accept Personal Identity Verification (PIV) credentials.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7738r365847_chk'
  tag severity: 'medium'
  tag gid: 'V-207481'
  tag rid: 'SV-207481r854655_rule'
  tag stig_id: 'SRG-OS-000376-VMM-001520'
  tag gtitle: 'SRG-OS-000376'
  tag fix_id: 'F-7738r365848_fix'
  tag 'documentable'
  tag legacy: ['V-57163', 'SV-71423']
  tag cci: ['CCI-001953']
  tag nist: ['IA-2 (12)']
end
