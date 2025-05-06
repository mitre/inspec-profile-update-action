control 'SV-51541' do
  title 'The organization must have a current ISP GIG Waiver for any ISP connections to the test and development environment.'
  desc "The test and development environment is typically a closed and physically separated network with no external connectivity to the DISN or Internet.  In some instances, Internet connectivity is needed for this environment due to the flexibility it provides for nonoperational systems.  In this case, an ISP GIG Waiver is required, along with approval from the organization's Authorizing Official."
  desc 'check', 'Verify the organization has an ISP GIG Waiver for any Internet connection.  The documentation should be up to date and included with the accreditation package.  If no ISP GIG Waiver has been obtained or is not up to date, this is a finding.'
  desc 'fix', 'Obtain an ISP GIG Waiver for any Internet connection into the test and development environment.'
  impact 0.3
  ref 'DPMS Target Test Enclave - Zone D'
  tag check_id: 'C-46829r1_chk'
  tag severity: 'low'
  tag gid: 'V-39674'
  tag rid: 'SV-51541r1_rule'
  tag stig_id: 'ENTD0350'
  tag gtitle: 'ENTD0350 - A current ISP GIG waiver does not exist.'
  tag fix_id: 'F-44682r1_fix'
  tag 'documentable'
end
