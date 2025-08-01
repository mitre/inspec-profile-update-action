control 'SV-51530' do
  title 'Access control lists between the test and development environment and DoD operational networks must be in a deny-by-default posture.'
  desc 'To prevent malicious or accidental leakage of traffic between test and development environments and operational networks, organizations must implement a deny-by-default security posture.  Perimeter routers, boundary controllers, or firewalls must deny incoming and outgoing traffic not expressly permitted.  Such rule sets prevent many malicious exploits or accidental leakage by regulating the ports, protocols, or services necessary to the enclave.'
  desc 'check', 'Determine whether a deny-by-default security posture has been implemented for both ingress and egress traffic between the test and development environment and DoD operational networks.  If the organization is not using a deny-by-default security posture for traffic between the test and development environment and DoD operational networks, this is a finding.'
  desc 'fix', 'Implement a deny-by-default security posture for both ingress and egress traffic between the test and development environment and DoD operational networks.'
  impact 0.7
  ref 'DPMS Target Test Enclave - Zone B'
  tag check_id: 'C-46818r1_chk'
  tag severity: 'high'
  tag gid: 'V-39663'
  tag rid: 'SV-51530r1_rule'
  tag stig_id: 'ENTD0240'
  tag gtitle: 'ENTD0240 - Access control lists not in deny-by-default security posture.'
  tag fix_id: 'F-44671r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
end
