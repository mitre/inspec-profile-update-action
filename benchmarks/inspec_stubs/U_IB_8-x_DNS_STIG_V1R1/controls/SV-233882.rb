control 'SV-233882' do
  title 'A secure out-of-band (OOB) network must be used for management of Infoblox Grid Members.'
  desc 'The Infoblox Grid Master is the central point of management within an Infoblox Grid. The Grid Master retains a full copy of the configuration used for the entire Grid. The Grid Master must communicate to Grid Members using their Management port connected to an OOB network that clients cannot access.'
  desc 'check', 'Note: For Infoblox DNS systems on a classified network, this requirement is Not Applicable.  

1. Navigate to Grid >> Grid Manager >> Members tab. 
2. Review the Grid Master network configuration and verify placement on an OOB network. 
3. Review services enabled on the Grid Master and verify that no client services are enabled.  
4. The only acceptable service allowed is DNS when the Grid uses DNSSEC signed zones. The Grid Master must have DNS enabled to sign DNSSEC zones.  

If DNSSEC is enabled, verify that the Grid Master is marked as "Stealth" for any zone.

If an Infoblox Grid Member does not use the MGMT port for configuration through an OOB connection, this is a finding.'
  desc 'fix', '1. Navigate to Grid >> Grid Manager >> Members tab. 
2. Edit each member and configure the MGMT port on the "Network" tab and enable VPN over MGMT on the "Advanced" portion of the "Network" tab.  
3. Grid Masters and Grid Master candidates use the LAN1 port for communication and should not allow any direct client access.'
  impact 0.7
  ref 'DPMS Target Infoblox 8.x DNS'
  tag check_id: 'C-37067r611166_chk'
  tag severity: 'high'
  tag gid: 'V-233882'
  tag rid: 'SV-233882r621666_rule'
  tag stig_id: 'IDNS-8X-400024'
  tag gtitle: 'SRG-APP-000516-DNS-000500'
  tag fix_id: 'F-37032r611167_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
