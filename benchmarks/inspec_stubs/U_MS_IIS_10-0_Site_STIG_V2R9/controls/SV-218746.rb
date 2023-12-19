control 'SV-218746' do
  title 'The IIS 10.0 website must have Web Distributed Authoring and Versioning (WebDAV) disabled.'
  desc 'A web server can be installed with functionality that by its nature is not secure. Web Distributed Authoring (WebDAV) is an extension to the HTTP protocol that, when developed, was meant to allow users to create, change, and move documents on a server, typically a web server or web share. Allowing this functionality, development, and deployment is much easier for web authors.

WebDAV is not widely used and has serious security concerns because it may allow clients to modify unauthorized files on the web server.'
  desc 'check', 'Follow the procedures below for each site hosted on the IIS 10.0 web server:

Open the IIS 10.0 Manager.

Select the IIS 10.0 website.

Review the features listed under the "IIS" section.

If the "WebDAV Authoring Rules" icon exists, this is a finding.'
  desc 'fix', 'Follow the procedures below for each site hosted on the IIS 10.0 web server:

Access Server Manager on the IIS 10.0 website.

Select the "Local Server".

Click "Manage".

Select "Add Roles and Features".

Click "Next" in the "Before you begin" dialog box.

Select "Role-based or feature-based installation" in the "Installation Type" dialog box and click "Next".

Select the IIS 10.0 web server on the "Server Selection" dialog box.

From the "Windows Features" dialog box, navigate to "World Wide Web Services" >> "Common HTTP Features".

De-select "WebDAV Publishing" and click "Next" to complete removing the WebDAV Publishing feature from the IIS 10.0 web server.

Select "Apply" from the "Actions" pane.'
  impact 0.5
  ref 'DPMS Target Microsoft IIS 10.0 Site'
  tag check_id: 'C-20219r311136_chk'
  tag severity: 'medium'
  tag gid: 'V-218746'
  tag rid: 'SV-218746r879587_rule'
  tag stig_id: 'IIST-SI-000217'
  tag gtitle: 'SRG-APP-000141-WSR-000085'
  tag fix_id: 'F-20217r311137_fix'
  tag 'documentable'
  tag legacy: ['SV-109317', 'V-100213']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
