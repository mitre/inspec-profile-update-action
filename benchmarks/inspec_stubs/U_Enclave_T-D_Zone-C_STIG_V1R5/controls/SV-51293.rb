control 'SV-51293' do
  title 'The organization must document impersistent connections to the test and development environment with approval by the organizations Authorizing Official.'
  desc 'An impersistent connection is any temporary connection needed to another test and development environment or DoD operational network where testing is not feasible.  As any unvetted connection or device will create additional risk and compromise the entire environment, it is up to the Authorizing Official for the organization to accept the risk of an impersistent connection.'
  desc 'check', 'Review documentation for impersistent connections or devices to ensure the risk has been thoroughly assessed and approved by the Authorizing Official.  If no documented approval is available for impersistent connections, this is a finding.'
  desc 'fix', 'Create and have on file up-to-date documentation of the authorized risk approval for impersistent connections or devices.'
  impact 0.5
  ref 'DPMS Target Test Enclave - Zone C'
  tag check_id: 'C-46709r3_chk'
  tag severity: 'medium'
  tag gid: 'V-39435'
  tag rid: 'SV-51293r1_rule'
  tag stig_id: 'ENTD0050'
  tag gtitle: 'ENTD0050 - Impersistent connections do not have approval.'
  tag fix_id: 'F-44448r4_fix'
  tag 'documentable'
  tag ia_controls: 'EBCR-1, ECSD-1'
end
