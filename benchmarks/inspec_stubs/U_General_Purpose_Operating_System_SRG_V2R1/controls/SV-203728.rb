control 'SV-203728' do
  title 'The operating system must accept Personal Identity Verification (PIV) credentials.'
  desc 'The use of PIV credentials facilitates standardization and reduces the risk of unauthorized access.

DoD has mandated the use of the CAC to support identity management and personal authentication for systems covered under Homeland Security Presidential Directive (HSPD) 12, as well as making the CAC a primary component of layered protection for national security systems.'
  desc 'check', 'Verify the operating system accepts Personal Identity Verification (PIV) credentials. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to accept Personal Identity Verification (PIV) credentials.'
  impact 0.5
  ref 'DPMS Target General Purpose Operating System'
  tag check_id: 'C-3853r375191_chk'
  tag severity: 'medium'
  tag gid: 'V-203728'
  tag rid: 'SV-203728r379855_rule'
  tag stig_id: 'SRG-OS-000376-GPOS-00161'
  tag gtitle: 'SRG-OS-000376'
  tag fix_id: 'F-3853r375192_fix'
  tag 'documentable'
  tag legacy: ['V-56815', 'SV-71075']
  tag cci: ['CCI-001953']
  tag nist: ['IA-2 (12)']
end
