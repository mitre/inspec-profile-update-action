control 'SV-225234' do
  title '.NET default proxy settings must be reviewed and approved.'
  desc "The .Net framework can be configured to utilize a different proxy or altogether bypass the default proxy settings in the client's browser.  This may lead to the framework using a proxy that is not approved for use.  If the proxy is malicious, this could lead to a loss of application integrity and confidentiality."
  desc 'check', 'Open Windows explorer and search for all "*.exe.config" and "machine.config" files.

Search each file for the "defaultProxy" element.

<defaultProxy
  enabled="true|false"
  useDefaultCredentials="true|false"
  <bypasslist> … </bypasslist>
  <proxy> … </proxy>
  <module> … </module>
/>

If the "defaultProxy" setting "enabled=false" or if the "bypasslist", "module", or "proxy" child elements have configuration entries and there are no documented approvals from the IAO, this is a finding.

 If the "defaultProxy" element is empty or if "useSystemDefault =True” then the framework is using default browser settings, this is not a finding.'
  desc 'fix', 'Open Windows explorer and search for all "*.exe.config" and "machine.config" files.

Search each file for the "defaultProxy" element.

Clear the values contained in the "defaultProxy" element, and the "bypasslist", "module", and "proxy" child elements.

The IAO must provide documented approvals of any non-default proxy servers.'
  impact 0.3
  ref 'DPMS Target Microsoft DotNet Framework 4-0'
  tag check_id: 'C-26933r864036_chk'
  tag severity: 'low'
  tag gid: 'V-225234'
  tag rid: 'SV-225234r864037_rule'
  tag stig_id: 'APPNET0066'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-26921r468018_fix'
  tag 'documentable'
  tag legacy: ['SV-41014', 'V-30972']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
