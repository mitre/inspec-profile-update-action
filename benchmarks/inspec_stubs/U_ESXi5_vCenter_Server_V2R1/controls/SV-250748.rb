control 'SV-250748' do
  title 'The Update Manager must not directly connect to public patch repositories on the Internet.'
  desc 'In a typical deployment, the Update Manager connects to public patch repositories on the Internet to download patches. Any channel to the Internet represents a threat. For security reasons and deployment restrictions, the Update Manager must be installed in a secured network that is disconnected from the Internet.'
  desc 'check', 'Verify the Update Manager download source is not the Internet. 

To verify download settings, from the vSphere Client/vCenter Server system, click Update Manager under Solutions and Applications.

On the Configuration tab, under Settings, click Download Settings. In the Download Sources pane, verify "Direct connection to Internet" is not selected.

If "Direct connection to Internet" is configured, this is a finding.'
  desc 'fix', 'To configure a Web server or local disk repository as a download source (i.e., "Direct connection to Internet" must not be selected as the source), from the vSphere Client/vCenter Server system, click Update Manager under Solutions and Applications. On the Configuration tab, under Settings, click Download Settings. In the Download Sources pane, select Use a shared repository. Enter the <site-specific> path or the URL to the shared repository. Click Validate URL to validate the path. Click Apply.'
  impact 0.5
  ref 'DPMS Target VMware vCenter Server Version 5'
  tag check_id: 'C-54183r799932_chk'
  tag severity: 'medium'
  tag gid: 'V-250748'
  tag rid: 'SV-250748r799934_rule'
  tag stig_id: 'VCENTER-000034'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-54137r799933_fix'
  tag 'documentable'
  tag legacy: ['SV-51427', 'V-39569']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
