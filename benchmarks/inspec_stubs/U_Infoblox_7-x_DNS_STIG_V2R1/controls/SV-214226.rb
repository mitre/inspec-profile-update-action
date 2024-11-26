control 'SV-214226' do
  title 'A secure Out Of Band (OOB) network must be utilized for management of Infoblox Grid Members.'
  desc 'The Infoblox Grid Master is the central point of management within an Infoblox Grid. The Grid Master retains a full copy of the configuration used for the entire Grid. The Grid Master should communicate to Grid Members using their Management port connected to an Out Of Band (OOB) network which clients cannot access.'
  desc 'check', 'Note: For Infoblox DNS systems on a Classified network, this requirement is Not Applicable.

Navigate to Grid >> Grid Manager >> Members tab.

Review the Grid Master network configuration and verify placement on an OOB network.

Review services enabled on the Grid Master and verify that no client services are enabled. The only acceptable service allowed is DNS when the Grid utilizes DNSSEC signed zones. The Grid Master must have DNS enabled to sign DNSSEC zones.

If DNSSEC is enabled, verify that the Grid Master marked as "Stealth" for any zone.

If an Infoblox Grid Member does not utilize the MGMT port for configuration through an OOB connection, this is a finding.'
  desc 'fix', 'Navigate to Grid >> Grid Manager >> Members tab.

Edit each member and configure the MGMT port on the Network tab and enable VPN over MGMT on the Advanced portion of the Network tab.
Grid Masters and Grid Master candidates utilize the LAN1 port for communication and should not allow any direct client access.'
  impact 0.5
  ref 'DPMS Target Infoblox 7.x DNS'
  tag check_id: 'C-15441r295941_chk'
  tag severity: 'medium'
  tag gid: 'V-214226'
  tag rid: 'SV-214226r612370_rule'
  tag stig_id: 'IDNS-7X-001010'
  tag gtitle: 'SRG-APP-000516-DNS-000500'
  tag fix_id: 'F-15439r295942_fix'
  tag 'documentable'
  tag legacy: ['SV-83109', 'V-68619']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
