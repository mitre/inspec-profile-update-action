control 'SV-216853' do
  title 'The vCenter Server for Windows must restrict the connectivity between Update Manager and public patch repositories by use of a separate Update Manager Download Server.'
  desc 'The Update Manager Download Service (UMDS) is an optional module of the Update Manager. UMDS downloads upgrades for virtual appliances, patch metadata, patch binaries, and notifications that would not otherwise be available to the Update Manager server. For security reasons and deployment restrictions, the Update Manager must be installed in a secured network that is disconnected from the Internet. The Update Manager requires access to patch information to function properly. UMDS must be installed on a separate system that has Internet access to download upgrades, patch binaries, and patch metadata, and then export the downloads to a portable media drive so that they become accessible to the Update Manager server.'
  desc 'check', 'Check the following conditions:
The Update Manager must be configured to use the Update Manager Download Server. 
The use of physical media to transfer update files to the Update Manager server (air gap model example: separate Update Manager Download Server which may source vendor patches externally via the Internet versus an internal, organization defined source) must be enforced with site policies.

Verify the Update Manager download source is not the Internet. 
To verify download settings, from the vSphere Client/vCenter Server system, click "Update Manager" under "Solutions and Applications".
On the "Configuration tab", under "Settings", click "Download Settings". In the "Download Sources" pane, verify "Direct connection to Internet" is not selected.

If "Direct connection to Internet" is configured, this is a finding.

If all of the above conditions are not met, this is a finding.'
  desc 'fix', 'Configure the Update Manager Server to use a separate Update Manager Download Server; the use of physical media to transfer updated files to the Update Manager server (air gap model) must be enforced and documented with organization policies. Configure the Update Manager Download Server and enable the Download Service. Patches must not be directly accessible to the Update Manager Server application from the Internet.

To configure a Web server or local disk repository as a download source (i.e., "Direct connection to Internet" must not be selected as the source), from the vSphere Client/vCenter Server system, click "Update Manager" under "Solutions and Applications". On the "Configuration" tab, under "Settings", click "Download Settings". In the "Download Sources" pane, select "Use a shared repository". Enter the <site-specific> path or the URL to the shared repository. Click "Validate URL" to validate the path. Click "Apply".'
  impact 0.3
  ref 'DPMS Target VMW vSphere 6.5 vCenter Server for Windows'
  tag check_id: 'C-18084r366273_chk'
  tag severity: 'low'
  tag gid: 'V-216853'
  tag rid: 'SV-216853r612237_rule'
  tag stig_id: 'VCWN-65-000031'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-18082r366274_fix'
  tag 'documentable'
  tag legacy: ['V-94771', 'SV-104601']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
