control 'SV-203729' do
  title 'The operating system must electronically verify Personal Identity Verification (PIV) credentials.'
  desc 'The use of PIV credentials facilitates standardization and reduces the risk of unauthorized access.

DoD has mandated the use of the CAC to support identity management and personal authentication for systems covered under Homeland Security Presidential Directive (HSPD) 12, as well as making the CAC a primary component of layered protection for national security systems.'
  desc 'check', 'Verify the operating system electronically verifies Personal Identity Verification (PIV) credentials. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to electronically verify Personal Identity Verification (PIV) credentials.'
  impact 0.5
  ref 'DPMS Target General Purpose Operating System'
  tag check_id: 'C-3854r375194_chk'
  tag severity: 'medium'
  tag gid: 'V-203729'
  tag rid: 'SV-203729r851800_rule'
  tag stig_id: 'SRG-OS-000377-GPOS-00162'
  tag gtitle: 'SRG-OS-000377'
  tag fix_id: 'F-3854r375195_fix'
  tag 'documentable'
  tag legacy: ['V-56813', 'SV-71073']
  tag cci: ['CCI-001954']
  tag nist: ['IA-2 (12)']
end
