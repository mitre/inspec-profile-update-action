control 'SV-218825' do
  title 'The IIS 10.0 web server must have a global authorization rule configured to restrict access.'
  desc 'Authorization rules can be configured at the server, website, folder (including Virtual Directories), or file level. It is recommended that URL Authorization be configured to only grant access to the necessary security principals. Configuring a global Authorization rule that restricts access ensures inheritance of the settings down through the hierarchy of web directories. This will ensure access to current and future content is only granted to the appropriate principals, mitigating risk of unauthorized access.'
  desc 'check', 'Open the IIS 10.0 Manager.

Click the IIS 10.0 web server name.

Double-click the ".NET Authorization Rules" icon.

If any groups other than "Administrators" are listed, this is a finding.

If ASP.NET is not installed, this is Not Applicable.

If the Server is hosting Microsoft SharePoint, this is Not Applicable.

If the server is hosting WSUS, this is Not Applicable.'
  desc 'fix', 'Open the IIS 10.0 Manager.

Click the IIS 10.0 web server name.

Double-click the "Authorization Rules" icon.

Remove all groups other than "Administrators".'
  impact 0.5
  ref 'DPMS Target Microsoft IIS 10.0 Server'
  tag check_id: 'C-20297r766896_chk'
  tag severity: 'medium'
  tag gid: 'V-218825'
  tag rid: 'SV-218825r766898_rule'
  tag stig_id: 'IIST-SV-000159'
  tag gtitle: 'SRG-APP-000516-WSR-000174'
  tag fix_id: 'F-20295r766897_fix'
  tag 'documentable'
  tag legacy: ['SV-109289', 'V-100185']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
