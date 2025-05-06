control 'SV-51528' do
  title 'Logical separation must occur between testing and development network segments within the same test and development environment.'
  desc 'Logical network segmentation is a way to restrict access between test and development systems to reduce the chance of code becoming victim to compromise.  Since test and development segments may not have the same level of IA assurance, logical separation is required.'
  desc 'check', 'Determine whether logical separation is present between test and development network segments.  Review the test and development network diagrams to ensure they have been properly documented.  If logical separation has not been established and documented between test and development network segments in the environment, this is a finding.'
  desc 'fix', 'Establish logical separation between test and development network segments in the environment.  Document the logical separation on the network diagrams.'
  impact 0.5
  ref 'DPMS Target Test Enclave - Zone B'
  tag check_id: 'C-46816r1_chk'
  tag severity: 'medium'
  tag gid: 'V-39661'
  tag rid: 'SV-51528r1_rule'
  tag stig_id: 'ENTD0220'
  tag gtitle: 'ENTD0220 - No logical separation between network segments.'
  tag fix_id: 'F-44669r1_fix'
  tag 'documentable'
  tag ia_controls: 'DCSP-1, ECSC-1'
end
