control 'SV-51529' do
  title 'Access control lists between development and testing network segments within a test and development environment must be in a deny-by-default posture.'
  desc 'To prevent malicious or accidental leakage of information between test and development environments, organizations must implement a deny-by-default security posture.  All traffic not explicitly permitted must be denied.  Such rule sets prevent many malicious exploits or accidental leakage by regulating the ports, protocols, or services necessary between network segments within the test and development environment.'
  desc 'check', 'Determine whether a deny-by-default security posture has been implemented for both ingress and egress traffic for the test and development environment.  If the organization is not using a deny-by-default security posture for ingress and ingress traffic for the test and development environment, this is a finding.'
  desc 'fix', 'Implement a deny-by-default security posture for both ingress and egress traffic between network segments in the test and development environment.'
  impact 0.3
  ref 'DPMS Target Test Enclave - Zone A'
  tag check_id: 'C-46817r1_chk'
  tag severity: 'low'
  tag gid: 'V-39662'
  tag rid: 'SV-51529r1_rule'
  tag stig_id: 'ENTD0230'
  tag gtitle: 'ENTD0230 - Access control lists not in deny-by-default posture.'
  tag fix_id: 'F-44670r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
end
