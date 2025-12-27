control 'SV-18889' do
  title 'A VTC endpoint must not bridge a wired LAN and a wireless LAN.'
  desc 'With increased use of wireless networks by DoD, the risk of accidentally or intentionally bridging networks of different security levels and requirements is rising. Unwanted network bridging is the act of connecting different IP networks against security policies and/or the intended network design. The network perimeter is changing and so are the possible vectors security threats can use. Improperly configured wireless adapters have the potential to provide backdoor connectivity, which ultimately can lead to the inadvertent disclosure of sensitive or classified information to individuals that may not have an appropriate need-to-know or proper security clearance.
A VTC system connected simultaneously to a wired LAN and an active wireless LAN/connection may permit traffic or control information to pass traffic between the two networks, thereby providing a bridge between the wired and wireless LAN connections. The unwanted network bridge is especially dangerous for VTC systems because often networks of different security policies and levels are used by the same equipment.'
  desc 'check', 'Verify VTC endpoints do not simultaneously connect to a wired LAN and a wireless LAN. If the VTC endpoint equipment can pass traffic between the two LANs, this is a finding.'
  desc 'fix', 'Configure the VTC system to prohibit simultaneous connection to a wireless LAN and a wired LAN connection.

NOTE: Best practice is to design the VTC endpoint unit with equipment that does not support wireless LAN connectivity or to insert an approved isolation switch between the networks connected to the VTC endpoint. For VTC endpoints relying on wireless connectivity for the conference room control system, cameras, or microphones, additional design considerations may be necessary to prevent bridging networks.'
  impact 0.7
  ref 'DPMS Target VTC Endpoint Site/System/Enclave'
  tag check_id: 'C-18985r2_chk'
  tag severity: 'high'
  tag gid: 'V-17715'
  tag rid: 'SV-18889r2_rule'
  tag stig_id: 'RTS-VTC 4320.00'
  tag gtitle: 'RTS-VTC 4320.00 [IP]'
  tag fix_id: 'F-17612r2_fix'
  tag 'documentable'
  tag severity_override_guidance: 'If the wired LAN and wireless LAN are in the same security domain and have the same classification, this finding may be downgraded to CAT II.'
  tag responsibility: 'System Administrator'
end
