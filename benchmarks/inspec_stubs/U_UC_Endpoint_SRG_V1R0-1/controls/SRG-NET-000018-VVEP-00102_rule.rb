control 'SRG-NET-000018-VVEP-00102_rule' do
  title 'The Unified Communications Endpoint must be configured to integrate into the implemented 802.1x network access control system.'
  desc 'IEEE 802.1x is a protocol used to control access to LAN services via a network access switchport or wireless access point that requires a device or user to authenticate to the network element and become authorized by the authentication server before accessing the network. This standard is used to activate the network access switchport limiting traffic to a specific VLAN or install traffic filters. Implementing 802.1x port security on each access switchport denies all other MAC users, which eliminates the security risk of additional users attaching to a switch to bypass authentication. The hardware Unified Communications Endpoint must be an 802.1x supplicant and integrate into the 802.1x access control system. When 802.1x is used, all devices connecting to the LAN are required to use 802.1x.

MAC Authentication Bypass is permitted by the Unified Communications Requirements Guide when the endpoint does not support 802.1x or required by mission continuity of operation requirements.'
  desc 'check', 'Verify the Unified Communications Endpoint is configured to integrate into the implemented 802.1x network access control system. 

If the Unified Communications Endpoint does not integrate into the implemented 802.1x network access control system, this is a finding.'
  desc 'fix', 'Configure the Unified Communications Endpoint to integrate into the implemented 802.1x network access control system.'
  impact 0.5
  tag check_id: 'C-SRG-NET-000018-VVEP-00102_chk'
  tag severity: 'medium'
  tag gid: 'SRG-NET-000018-VVEP-00102'
  tag rid: 'SRG-NET-000018-VVEP-00102_rule'
  tag stig_id: 'SRG-NET-000018-VVEP-00102'
  tag gtitle: 'SRG-NET-000018-VVEP-00102'
  tag fix_id: 'F-SRG-NET-000018-VVEP-00102_fix'
  tag 'documentable'
  tag cci: ['CCI-001368']
  tag nist: ['AC-4']
end
