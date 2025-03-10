control 'SV-254071' do
  title 'The Juniper router must be configured to advertise a hop limit of at least 32 in Router Advertisement messages for IPv6 stateless auto-configuration deployments.'
  desc 'The Neighbor Discovery protocol allows a hop limit value to be advertised by routers in a Router Advertisement message being used by hosts instead of the standardized default value. If a very small value was configured and advertised to hosts on the LAN segment, communications would fail due to the hop limit reaching zero before the packets sent by a host reached its destination.'
  desc 'check', 'This requirement is not applicable for the DODIN Backbone. 

Review the router configuration to determine if the hop limit has been configured for Router Advertisement messages. Verify each interface configured for router advertisements contains a hop limit of at least 32.

[edit protocols]
router-advertisement {
    interface ge-0/0/0.0 {
        :
        current-hop-limit 32; <<< Supported values: 0 - 255 
        :
    }
}

If it has been configured and has not been set to at least 32, it is a finding.'
  desc 'fix', 'Configure the router to advertise a hop limit of at least 32 in Router Advertisement messages.

set protocols router-advertisement interface <internal interface> current-hop-limit <32 or greater>'
  impact 0.3
  ref 'DPMS Target Juniper EX Series Switches Router'
  tag check_id: 'C-57523r844244_chk'
  tag severity: 'low'
  tag gid: 'V-254071'
  tag rid: 'SV-254071r844246_rule'
  tag stig_id: 'JUEX-RT-000990'
  tag gtitle: 'SRG-NET-000512-RTR-000012'
  tag fix_id: 'F-57474r844245_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
