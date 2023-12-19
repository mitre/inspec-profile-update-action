control 'SV-258596' do
  title 'The ICS must be configured to disable split-tunneling for remote client VPNs.'
  desc "Split tunneling would in effect allow unauthorized external connections, making the system more vulnerable to attack and to exfiltration of organizational information.

A VPN hardware or software client with split tunneling enabled provides an unsecured backdoor to the enclave from the internet. With split tunneling enabled, a remote client has access to the internet while at the same time has established a secured path to the enclave via an IPsec tunnel. A remote client connected to the internet that has been compromised by an attacker on the internet, provides an attack base to the enclave's private network via the IPsec tunnel. Hence, it is imperative that the VPN gateway enforces a no split-tunneling policy to all remote clients."
  desc 'check', 'In the ICS Web UI, navigate to Users >> Resource Policies >> Split Tunneling Networks.

If there are any split-tunnel network policies, this is a finding.'
  desc 'fix', 'In the ICS Web UI, navigate to Users >> Resource Policies >> Split Tunneling Networks.
1. If there are any split-tunnel network policies configured, select all of them and delete them.
2. If the split tunneling policies are needed for debugging or testing only, ensure the role being applied is only for the debugging or test group.'
  impact 0.5
  ref 'DPMS Target Ivanti Connect Secure VPN'
  tag check_id: 'C-62336r930474_chk'
  tag severity: 'medium'
  tag gid: 'V-258596'
  tag rid: 'SV-258596r930476_rule'
  tag stig_id: 'IVCS-VN-000360'
  tag gtitle: 'SRG-NET-000369-VPN-001620'
  tag fix_id: 'F-62245r930475_fix'
  tag 'documentable'
  tag cci: ['CCI-002397']
  tag nist: ['SC-7 (7)']
end
