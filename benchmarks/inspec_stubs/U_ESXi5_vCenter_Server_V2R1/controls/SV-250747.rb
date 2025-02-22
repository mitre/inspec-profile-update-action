control 'SV-250747' do
  title 'The Update Manager Download Server must be isolated from direct connection to Internet public patch repositories by a proxy server.'
  desc 'In a typical deployment, the Update Manager Download Server connects to public patch repositories on the Internet to download patches. This connection must be restricted as much as possible to prevent access from the outside to the Update Manager Download Server. Any direct channel to the Internet represents a threat.'
  desc 'check', 'If the Update Manager Download Server does not connect to the Internet to source vendor patches, this check is not applicable.

Verify there is a Web proxy between Update Manager Download Server and the Internet. Check the proxy settings for the Update Manager Download Server to ensure correct configuration. 

To verify proxy settings, from the vSphere Client/vCenter Server system, click Update Manager under Solutions and Applications.

On the Configuration tab, under Settings, click Download Settings.
In the Proxy Settings pane, select properties and view the proxy information.

If a web proxy between Update Manager Download Server and the Internet is not configured, this is a finding.'
  desc 'fix', 'If the Update Manager Download Server does not connect to the Internet to source vendor patches, no fix is required.

To configure proxy settings, from the vSphere Client/vCenter Server system, click Update Manager under Solutions and Applications.

On the Configuration tab, under Settings, click Download Settings. In the Proxy Settings pane, select Use proxy and change the proxy information. Optional: If the proxy requires authentication, select Proxy requires authentication and provide a user name and password. Optional: Click Test Connection at any time to test  a connection to the Internet through the proxy is possible. Click Apply.'
  impact 0.5
  ref 'DPMS Target VMware vCenter Server Version 5'
  tag check_id: 'C-54182r799929_chk'
  tag severity: 'medium'
  tag gid: 'V-250747'
  tag rid: 'SV-250747r799931_rule'
  tag stig_id: 'VCENTER-000033'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-54136r799930_fix'
  tag 'documentable'
  tag legacy: ['V-39568', 'SV-51426']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
