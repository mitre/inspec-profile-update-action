control 'SV-51298' do
  title 'Development systems must be part of a patch management solution.'
  desc 'Major software vendors release security patches and hotfixes to their products when security vulnerabilities are discovered.  It is essential that these updates be applied in a timely manner to prevent unauthorized individuals from exploiting identified vulnerabilities.'
  desc 'check', "Determine whether the organization has a patch management solution in place to apply security patches released by the vendor.  If a patch management solution has not been implemented and is not functioning to update development systems with the latest patches, this is a finding.

If there isn't any application development occurring in the zone environment, this requirement is not applicable."
  desc 'fix', 'Implement a patch management solution to keep development systems up to date with the latest security patches released by the vendor.'
  impact 0.5
  ref 'DPMS Target Test Enclave - Zone C'
  tag check_id: 'C-46715r3_chk'
  tag severity: 'medium'
  tag gid: 'V-39440'
  tag rid: 'SV-51298r1_rule'
  tag stig_id: 'ENTD0100'
  tag gtitle: 'ENTD0100 - A patch management solution is not implemented for development systems.'
  tag fix_id: 'F-44453r2_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1, VIVM-1'
end
