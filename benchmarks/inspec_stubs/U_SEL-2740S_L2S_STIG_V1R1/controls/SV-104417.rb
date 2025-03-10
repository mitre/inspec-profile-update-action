control 'SV-104417' do
  title 'The SEL-2740S must authenticate all network-connected endpoint devices before establishing any connection.'
  desc 'Without authenticating devices, unidentified or unknown devices may be introduced, thereby facilitating malicious activity.

For distributed architectures (e.g., service-oriented architectures), the decisions regarding the validation of authentication claims may be made by services separate from the services acting on those decisions. In such situations, it is necessary to provide authentication decisions (as opposed to the actual authenticators) to the services that need to act on those decisions.

This requirement applies to applications that connect either locally, remotely, or through a network to an endpoint device (including, but not limited to, workstations, printers, servers (outside a datacenter), VoIP Phones, and VTC CODECs). Gateways and SOA applications are examples of where this requirement would apply.

Device authentication is a solution enabling an organization to manage devices. It is an additional layer of authentication ensuring only specific pre-authorized devices can access the system.'
  desc 'check', 'This finding can be downgraded to a CAT III if there is no horizontal cabling from the switch to the general work area. 

Verify that all cabling is contained within the telecom room, wiring closet, or equipment room. 

If there is cabling from the switch to LAN outlets (i.e.RJ-45 wall plates) in the general work area, this is a CAT II finding.

If all cabling is contained within the telecom room, wiring closet, or equipment room, this is a CAT III finding.'
  desc 'fix', 'Ensure there is no horizontal cabling from the switch to the general work area. 

Verify that all cabling is contained within the telecom room, wiring closet, or equipment room.'
  impact 0.5
  ref 'DPMS Target SEL SDN Switch L2S'
  tag check_id: 'C-93777r1_chk'
  tag severity: 'medium'
  tag gid: 'V-94587'
  tag rid: 'SV-104417r2_rule'
  tag stig_id: 'SELS-SW-000090'
  tag gtitle: 'SRG-NET-000343-L2S-000016'
  tag fix_id: 'F-100705r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001958']
  tag nist: ['IA-3']
end
