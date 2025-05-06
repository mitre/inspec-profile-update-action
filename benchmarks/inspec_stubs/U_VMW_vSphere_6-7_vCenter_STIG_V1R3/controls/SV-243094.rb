control 'SV-243094' do
  title 'The vCenter Server must restrict the connectivity between Update Manager and public patch repositories by use of a separate Update Manager Download Server.'
  desc 'The Update Manager Download Service (UMDS) is an optional module of the Update Manager. UMDS downloads upgrades for virtual appliances, patch metadata, patch binaries, and notifications that would not otherwise be available to the Update Manager server. 

For security reasons and deployment restrictions, the Update Manager must be installed in a secured network that is disconnected from the internet. The Update Manager requires access to patch information to function properly. UMDS must be installed on a separate system that has internet access to download upgrades, patch binaries, and patch metadata and then export the downloads to a portable media drive so they become accessible to the Update Manager server.'
  desc 'check', 'Check the following conditions:

1. The Update Manager must be configured to use the Update Manager Download Server. 

2. The use of physical media to transfer update files to the Update Manager server (air gap model example: separate Update Manager Download Server, which may source vendor patches externally via the internet versus an internal, organization-defined source) must be enforced with site policies.

From the vSphere Client, click Update Manager >> Settings >> Administrative Settings >> Patch Setup and click the "Change Download Source" button. 

Verify that the "Download patches from a UMDS shared repository" radio button is selected and that a valid UMDS repository is supplied.

If "Direct connection to Internet" is configured, this is a finding.

If all of the above conditions are not met, this is a finding.'
  desc 'fix', 'Configure the Update Manager Server to use a separate Update Manager Download Server; the use of physical media to transfer updated files to the Update Manager server (air gap model) must be enforced and documented with organization policies. 

Configure the Update Manager Download Server and enable the Download Service. Patches must not be directly accessible to the Update Manager Server application from the internet.

To configure a web server or local disk repository as a download source (i.e., "Direct connection to Internet" must not be selected as the source), from the vSphere Client/vCenter Server system, click "Update Manager" under "Solutions and Applications". 

On the "Configuration" tab, under "Settings", click "Download Settings". 

In the "Download Sources" pane, select "Use a shared repository". 

Enter the <site-specific> path or the URL to the shared repository. 

Click "Validate URL" to validate the path. 

Click "Apply".'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 vCenter'
  tag check_id: 'C-46369r719523_chk'
  tag severity: 'medium'
  tag gid: 'V-243094'
  tag rid: 'SV-243094r719525_rule'
  tag stig_id: 'VCTR-67-000031'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-46326r719524_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
