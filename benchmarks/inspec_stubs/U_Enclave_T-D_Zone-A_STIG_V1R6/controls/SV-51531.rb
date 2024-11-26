control 'SV-51531' do
  title 'Access control lists between the test and development environments must be in a deny-by-default posture.'
  desc 'To prevent malicious or accidental leakage of traffic, organizations must implement a deny-by-default security posture between test and development environments.  All ingress and egress traffic not explicitly permitted between test and development environments must be denied. Such rule sets prevent many malicious exploits or accidental leakage by regulating the ports, protocols, or services necessary to each environment.'
  desc 'check', 'Determine whether a deny-by-default security posture has been implemented for both ingress and egress traffic between the test and development environments.  If the organization is not using a deny-by-default security posture for traffic between the test and development environments, this is a finding.'
  desc 'fix', 'Implement a deny-by-default security posture for both ingress and egress traffic between test and development environments.'
  impact 0.5
  ref 'DPMS Target Test Enclave - Zone A'
  tag check_id: 'C-46819r1_chk'
  tag severity: 'medium'
  tag gid: 'V-39664'
  tag rid: 'SV-51531r1_rule'
  tag stig_id: 'ENTD0250'
  tag gtitle: 'ENTD0250 - Access control lists not in deny-by-default security posture.'
  tag fix_id: 'F-44672r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
end
