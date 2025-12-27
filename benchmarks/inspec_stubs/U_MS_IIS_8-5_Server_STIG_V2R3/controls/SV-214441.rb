control 'SV-214441' do
  title 'The IIS 8.5 web server must have a global authorization rule configured to restrict access.'
  desc 'Authorization rules can be configured at the server, website, folder (including Virtual Directories), or file level. It is recommended that URL Authorization be configured to only grant access to the necessary security principals. Configuring a global Authorization rule that restricts access ensures inheritance of the settings down through the hierarchy of web directories. This will ensure access to current and future content is only granted to the appropriate principals, mitigating risk of unauthorized access.'
  desc 'check', 'If ASP.NET is not installed, this is Not Applicable.
If the server is hosting SharePoint, this is Not Applicable.
If the server is hosting WSUS, this is Not Applicable.
If the server is hosting Exchange, this is Not Applicable.

Open the IIS 8.5 Manager.

Click the IIS 8.5 web server name.

Double-click the “.NET Authorization Rules” icon.

If any groups other than “Administrators” are listed, this is a finding.'
  desc 'fix', 'If ASP.NET is not installed, this is Not Applicable.
If the server is hosting SharePoint, this is Not Applicable.
If the server is hosting WSUS, this is Not Applicable.
If the server is hosting Exchange, this is Not Applicable.

Open the IIS 8.5 Manager.

Click the IIS 8.5 web server name.

Double-click the “Authorization Rules” icon.

Remove all groups other than “Administrators”.'
  impact 0.5
  ref 'DPMS Target Microsoft IIS 8.5 Server'
  tag check_id: 'C-15651r802872_chk'
  tag severity: 'medium'
  tag gid: 'V-214441'
  tag rid: 'SV-214441r802874_rule'
  tag stig_id: 'IISW-SV-000159'
  tag gtitle: 'SRG-APP-000516-WSR-000174'
  tag fix_id: 'F-15649r802873_fix'
  tag 'documentable'
  tag legacy: ['SV-91467', 'V-76771']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
