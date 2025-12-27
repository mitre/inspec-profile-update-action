control 'SV-51298' do
  title 'Development systems must be part of a patch management solution and all systems must be up to date.'
  desc 'Major software vendors release security patches and hotfixes to their products when security vulnerabilities are discovered.  It is essential that these updates be applied in a timely manner to prevent unauthorized individuals from exploiting identified vulnerabilities.'
  desc 'check', 'Determine whether the organization has a patch management solution in place to apply security patches released by the vendor, and that all systems are up to date.  If a patch management solution has not been implemented and is not functioning to update development systems with the latest patches, or all systems are not up to date, this is a finding.'
  desc 'fix', 'Implement a patch management solution to keep development systems up to date with the latest security patches released by the vendor.'
  impact 0.7
  ref 'DPMS Target Test Enclave - Zone A'
  tag check_id: 'C-46715r3_chk'
  tag severity: 'high'
  tag gid: 'V-39440'
  tag rid: 'SV-51298r1_rule'
  tag stig_id: 'ENTD0100'
  tag gtitle: 'ENTD0100 - A patch management solution is not implemented for development systems, and all systems not up to date.'
  tag fix_id: 'F-44453r2_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1, VIVM-1'
end
