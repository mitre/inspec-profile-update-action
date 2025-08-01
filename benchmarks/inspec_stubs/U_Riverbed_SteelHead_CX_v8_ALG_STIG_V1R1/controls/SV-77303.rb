control 'SV-77303' do
  title 'The Riverbed Optimization System (RiOS) must be configured to ensure inbound and outbound traffic is forwarded to be inspected by the firewall and IDPS in compliance with remote access security policies.'
  desc "Automated monitoring of remote access traffic allows organizations to detect cyber attacks and also ensure ongoing compliance with remote access policies by inspecting connection activities of remote access capabilities.

Remote access methods include both unencrypted and encrypted traffic. Inbound traffic must be inspected prior to being allowed on the enclave's trusted networks. Outbound traffic inspection must occur prior to being forwarded to destinations outside of the enclave.

Optimally, the SteelHead must be architecturally placed at the perimeter in front of the perimeter router. Thus, traffic is directed for firewall and IDPS inspection for inbound and outbound traffic in compliance with DoD policy. Additionally, from an operational perspective, this architecture avoids the need to open many ports and services in the firewall to accommodate TCP options 76 and 78 and ports 7800, 7810, and 7870. Some other configurations may involve even more ports and services."
  desc 'check', 'Inspect the architectural placement of the device. Verify the traffic from the device is directed to the firewall and IDS or IPS for inspection.

If RiOS is not configured to ensure inbound and outbound traffic is forwarded to be inspected by the firewall and IDPS in compliance with remote access security policies, this is a finding.'
  desc 'fix', 'Architecturally place the SteelHead device to avoid the need to open TCP ports in the firewall. The recommended best practice for this device is to install it at the perimeter in front of the perimeter router and direct and configure to direct traffic to the router. Thus, inbound and outbound traffic is forwarded to be inspected by the firewall and IDPS in compliance with remote access security policies.'
  impact 0.5
  ref 'DPMS Target Riverbed SteelHead CX Version 8 ALG'
  tag check_id: 'C-63607r1_chk'
  tag severity: 'medium'
  tag gid: 'V-62813'
  tag rid: 'SV-77303r1_rule'
  tag stig_id: 'RICX-AG-000037'
  tag gtitle: 'SRG-NET-000061-ALG-000009'
  tag fix_id: 'F-68731r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000067']
  tag nist: ['AC-17 (1)']
end
