control 'SV-214414' do
  title 'The IIS 8.5 web server must have Web Distributed Authoring and Versioning (WebDAV) disabled.'
  desc 'A web server can be installed with functionality that, just by its nature, is not secure. Web Distributed Authoring (WebDAV) is an extension to the HTTP protocol that, when developed, was meant to allow users to create, change, and move documents on a server, typically a web server or web share. Allowing this functionality, development, and deployment is much easier for web authors.

WebDAV is not widely used and has serious security concerns because it may allow clients to modify unauthorized files on the web server.'
  desc 'check', 'Open the IIS 8.5 Manager.

Click the IIS 8.5 web server name.

Review the features listed under the “IIS" section.

If the "WebDAV Authoring Rules" icon exists, this is a finding.'
  desc 'fix', 'Access Server Manager on the IIS 8.5 web server.

Click the IIS 8.5 web server name.

Click on "Manage".

Select "Add Roles and Features".

Click "Next" on the "Before you begin" dialog box.

Select "Role-based or feature-based installation" on the "Installation Type" dialog box and click on "Next".

Select the IIS 8.5 web server on the "Server Selection" dialog box.

From the "Windows Features" dialog box, navigate to "World Wide Web Services" >> "Common HTTP Features".

De-select "WebDAV Publishing" and click "Next" to complete removing the WebDAV Publishing feature from the IIS 8.5 web server.'
  impact 0.5
  ref 'DPMS Target Microsoft IIS 8.5 Server'
  tag check_id: 'C-15624r310290_chk'
  tag severity: 'medium'
  tag gid: 'V-214414'
  tag rid: 'SV-214414r508658_rule'
  tag stig_id: 'IISW-SV-000125'
  tag gtitle: 'SRG-APP-000141-WSR-000085'
  tag fix_id: 'F-15622r310291_fix'
  tag 'documentable'
  tag legacy: ['SV-91409', 'V-76713']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
