control 'SV-51479' do
  title 'The organization must sanitize data transferred to test and development environments from DoD operational networks for testing to remove personal and sensitive information exempt from the Freedom of Information Act.'
  desc 'If DoD production data is transferred to a test and development environment and personal or sensitive information has not been sanitized from the data, personal or sensitive information could be exposed or compromised.'
  desc 'check', 'Determine the data type on systems within the test and development environment.  Interview the ISSM or ISSO regarding the connection approval process for housing DoD live operational data or Privacy Act information on any test or development system.  If the test and development environment is using live DoD data or Privacy Act information, this is a finding.'
  desc 'fix', 'Create organizational policies and procedures to prohibit the use of any live operational DoD data or Privacy Act information in the test and development environment.'
  impact 0.5
  ref 'DPMS Target Test Enclave - Zone C'
  tag check_id: 'C-46799r3_chk'
  tag severity: 'medium'
  tag gid: 'V-39621'
  tag rid: 'SV-51479r2_rule'
  tag stig_id: 'ENTD0150'
  tag gtitle: 'ENTD0150 - Operational data is not sanitized prior to testing.'
  tag fix_id: 'F-44637r2_fix'
  tag 'documentable'
end
