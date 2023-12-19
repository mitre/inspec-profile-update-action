control 'SV-250731' do
  title 'The connectivity between Update Manager and public patch repositories must be restricted by use of a separate Update Manager Download Server.'
  desc 'The Update Manager Download Service (UMDS) is an optional module of the Update Manager. UMDS downloads upgrades for virtual appliances, patch metadata, patch binaries, and notifications that would not otherwise be available to the Update Manager server. For security reasons and deployment restrictions, the Update Manager must be installed in a secured network that is disconnected from the Internet. The Update Manager requires access to patch information to function properly. UMDS must be installed on a separate system that has Internet access to download upgrades, patch binaries, and patch metadata, and then export the downloads to a portable media drive so that they become accessible to the Update Manager server.'
  desc 'check', 'Check the following conditions:
The Update Manager must be configured to use the Update Manager Download Server. 
The use of physical media to transfer update files to the Update Manager server (air-gap model example: separate Update Manager Download Server which may source vendor patches externally via the Internet versus an internal,  organization defined source) must be enforced with site policies.

If all of the above conditions are not met, this is a finding.'
  desc 'fix', 'Configure the Update Manager Server to use a separate Update Manager Download Server; the use of physical media to transfer updated files to the Update Manager server (air-gap model) must be enforced and documented with organization policies. Configure the Update Manager Download Server and enable the Download Service. Patches must not be directly accessible to the Update Manager Server application from the Internet.'
  impact 0.3
  ref 'DPMS Target VMware vCenter Server Version 5'
  tag check_id: 'C-54166r799881_chk'
  tag severity: 'low'
  tag gid: 'V-250731'
  tag rid: 'SV-250731r799883_rule'
  tag stig_id: 'VCENTER-000009'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-54120r799882_fix'
  tag 'documentable'
  tag legacy: ['V-39549', 'SV-51407']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
