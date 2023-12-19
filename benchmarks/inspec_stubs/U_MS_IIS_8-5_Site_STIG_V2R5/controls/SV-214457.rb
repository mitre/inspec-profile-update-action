control 'SV-214457' do
  title 'The IIS 8.5 website must have Web Distributed Authoring and Versioning (WebDAV) disabled.'
  desc 'A web server can be installed with functionality that, just by its nature, is not secure. Web Distributed Authoring (WebDAV) is an extension to the HTTP protocol that, when developed, was meant to allow users to create, change, and move documents on a server, typically a web server or web share. Allowing this functionality, development, and deployment is much easier for web authors.

WebDAV is not widely used and has serious security concerns because it may allow clients to modify unauthorized files on the web server.'
  desc 'check', 'Follow the procedures below for each site hosted on the IIS 8.5 web server:

Open the IIS 8.5 Manager.

Select the IIS 8.5 website.

Review the features listed under the "IIS" section.

If the "WebDAV Authoring Rules" icon exists, this is a finding.'
  desc 'fix', 'Follow the procedures below for each site hosted on the IIS 8.5 web server:

Access Server Manager on the IIS 8.5 website.

Select the Local Server.

Click on "Manage".

Select "Add Roles and Features".

Click "Next" on the "Before you begin" dialog box.

Select "Role-based or feature-based installation" on the "Installation Type" dialog box and click on "Next".

Select the IIS 8.5 web server on the "Server Selection" dialog box.

From the "Windows Features" dialog box, navigate to "World Wide Web Services" >> "Common HTTP Features".

De-select "WebDAV Publishing" and click "Next" to complete removing the WebDAV Publishing feature from the IIS 8.5 web server.

Select "Apply" from the "Actions" pane.'
  impact 0.5
  ref 'DPMS Target Microsoft IIS 8.5 Site'
  tag check_id: 'C-15666r310575_chk'
  tag severity: 'medium'
  tag gid: 'V-214457'
  tag rid: 'SV-214457r508659_rule'
  tag stig_id: 'IISW-SI-000217'
  tag gtitle: 'SRG-APP-000141-WSR-000085'
  tag fix_id: 'F-15664r310576_fix'
  tag 'documentable'
  tag legacy: ['SV-91499', 'V-76803']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
