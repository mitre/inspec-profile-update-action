control 'SV-51536' do
  title 'Remote access VPNs must prohibit the use of split tunneling on VPN connections.'
  desc 'The VPN software on a host can be configured in either of two modes. It can be set to encrypt all IP traffic originating from that host, and send all of that traffic to the remote IP address of the network gateway. This configuration is called “tunnel-all” mode, because all IP traffic from the host must traverse the VPN tunnel to the remote system, where it will either be processed or further forwarded to additional IP addresses after decryption. Alternately, the VPN software can be set only to encrypt traffic that is specifically addressed to an IP at the other end of the VPN tunnel. All other IP traffic bypasses the VPN encryption and routing process, and is handled by the host as if the VPN relationship did not exist. This configuration is called “split-tunnel” mode, because the IP traffic from the host is split between encrypted packets sent across the VPN tunnel and unencrypted packets sent to all other external addresses. There are security and operational implications in the decision of whether to use split-tunnel or tunnel-all mode. Placing a host in tunnel-all mode makes it appear to the rest of the world as a node on the connected logical (VPN-connected) network. It no longer has an identity to the outside world based on the local physical network. In tunnel-all mode, all traffic between the remote host and any other host can be subject to inspection and processing by the security policy devices of the remote VPN-linked network. This improves the security aspects of the connected network, since it can enforce all security policies on the VPN-connected computer.'
  desc 'check', 'Determine whether split tunneling is prohibited for remote access VPNs connecting to the test and development environment.  If the VPN policy allows split tunneling, this is a finding.'
  desc 'fix', 'Configure VPNs to prohibit split tunneling when connecting to the test and development environment.'
  impact 0.5
  ref 'DPMS Target Test Enclave - Zone B'
  tag check_id: 'C-46824r1_chk'
  tag severity: 'medium'
  tag gid: 'V-39669'
  tag rid: 'SV-51536r1_rule'
  tag stig_id: 'ENTD0300'
  tag gtitle: 'ENTD0300 - Remote access VPN policies do not disable split tunneling.'
  tag fix_id: 'F-44677r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
end
