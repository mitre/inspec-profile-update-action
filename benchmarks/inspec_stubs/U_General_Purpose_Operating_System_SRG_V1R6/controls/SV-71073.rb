control 'SV-71073' do
  title 'The operating system must electronically verify Personal Identity Verification (PIV) credentials.'
  desc 'The use of PIV credentials facilitates standardization and reduces the risk of unauthorized access.

DoD has mandated the use of the CAC to support identity management and personal authentication for systems covered under Homeland Security Presidential Directive (HSPD) 12, as well as making the CAC a primary component of layered protection for national security systems.'
  desc 'check', 'Verify the operating system electronically verifies Personal Identity Verification (PIV) credentials. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to electronically verify Personal Identity Verification (PIV) credentials.'
  impact 0.5
  ref 'DPMS Target SRG-OS-GPOS'
  tag check_id: 'C-57383r1_chk'
  tag severity: 'medium'
  tag gid: 'V-56813'
  tag rid: 'SV-71073r1_rule'
  tag stig_id: 'SRG-OS-000377-GPOS-00162'
  tag gtitle: 'SRG-OS-000377-GPOS-00162'
  tag fix_id: 'F-61709r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001954']
  tag nist: ['IA-2 (12)']
end
