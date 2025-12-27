control 'SV-218825' do
  title 'The IIS 10.0 web server must have a global authorization rule configured to restrict access.'
  desc 'Authorization rules can be configured at the server, website, folder (including Virtual Directories), or file level. It is recommended that URL Authorization be configured to only grant access to the necessary security principals. Configuring a global Authorization rule that restricts access ensures inheritance of the settings down through the hierarchy of web directories. This will ensure access to current and future content is only granted to the appropriate principals, mitigating risk of unauthorized access.'
  desc 'check', 'Note: If ASP.NET is not installed, this is Not Applicable.
Note: If the Server is hosting Microsoft SharePoint, this is Not Applicable.
Note: If the server is hosting WSUS, this is Not Applicable.
Note: If the server is hosting Exchange, this is Not Applicable.
Note: If the server is public facing, this is Not Applicable.

Open the IIS 10.0 Manager.

Click the IIS 10.0 web server name.

Double-click the ".NET Authorization Rules" icon.

Ensure "All Users" is set to "Allow", and "Anonymous Users" is set to "Deny", otherwise this is a finding.
If any other rules are present, this is a finding.'
  desc 'fix', 'Open the IIS 10.0 Manager.

Click the IIS 10.0 web server name.

Double-click the ".NET Authorization Rules" icon.

Alter the list as necessary to ensure "All Users" is set to "Allow" and "Anonymous Users" is set to "Deny".

Remove any other line items.'
  impact 0.5
  ref 'DPMS Target Microsoft IIS 10.0 Server'
  tag check_id: 'C-20297r928845_chk'
  tag severity: 'medium'
  tag gid: 'V-218825'
  tag rid: 'SV-218825r928846_rule'
  tag stig_id: 'IIST-SV-000159'
  tag gtitle: 'SRG-APP-000516-WSR-000174'
  tag fix_id: 'F-20295r881081_fix'
  tag 'documentable'
  tag legacy: ['SV-109289', 'V-100185']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
