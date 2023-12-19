control 'SV-55759' do
  title 'The IP-based VTC system must authenticate to an H.323 Gatekeeper or VVoIP session/call controller.'
  desc 'An IP-based VTC system must authenticate itself to an H.323 Gatekeeper or VVoIP session/call controller for the purposes of access control, authorization, and WAN access bandwidth management. An H.323 Gatekeeper or VVoIP session/call controller is a dedicated device or application that controls the manner in which phone calls are initiated, conducted, and terminated and is often one of the main components in H.323 systems. It serves the purpose of Call Admission Control and translation services from E.164 IDs (commonly a phone number) to IP addresses in an H.323 telephony network. It also provides bandwidth control.

In general, all VTC system management applications and application suites, including endpoint and MCU managers, gateways, gatekeepers, controllers, and scheduling systems must be operated on secure or hardened platforms and comply with all applicable DoD STIGs with specific emphasis on user accounts, roles/permissions, access control, and auditing.'
  desc 'check', 'Review the system documentation and verify that an H.323 Gatekeeper and/or VVoIP session/call controller is in place and is configured to require authentication of endpoints. If there is no H.323 Gatekeeper or VVoIP session/call controller present; or it is not configured to require authentication of endpoints; or endpoints are not configured to authenticate with either, this is a finding.'
  desc 'fix', 'Configure the endpoints and H.323 Gatekeeper or VVoIP session/call controller to authenticate endpoints.'
  impact 0.5
  ref 'DPMS Target VTC Endpoint Site/System/Enclave'
  tag check_id: 'C-49186r5_chk'
  tag severity: 'medium'
  tag gid: 'V-43030'
  tag rid: 'SV-55759r1_rule'
  tag stig_id: 'RTS-VTC 5040'
  tag gtitle: 'RTS-VTC 5040 [IP]'
  tag fix_id: 'F-48614r3_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
  tag ia_controls: 'IAIA-1'
end
