control 'SV-51535' do
  title 'The organization must prohibit remote access from external networks to the test and development environment.'
  desc 'Because the test and development environment is a closed network, any network or remote access from outside the designated environment boundaries is prohibited.  Allowing remote access from an untrusted external network will leave the network open to attacks and compromised.'
  desc 'check', "Verify the organization's policies and procedures to prohibit remote access to the test and development environment from external networks.  If policies and procedures are not available to prohibit remote access to the test and development environment from external networks, this is a finding."
  desc 'fix', 'Prohibit remote access to the test and development environment from external networks.'
  impact 0.3
  ref 'DPMS Target Test Enclave - Zone C'
  tag check_id: 'C-46823r3_chk'
  tag severity: 'low'
  tag gid: 'V-39668'
  tag rid: 'SV-51535r1_rule'
  tag stig_id: 'ENTD0290'
  tag gtitle: 'ENTD0290 - Remote access to the environment is not prohibited.'
  tag fix_id: 'F-44676r3_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
end
