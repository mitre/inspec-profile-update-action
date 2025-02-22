control 'SV-206383' do
  title 'The web server must have Web Distributed Authoring (WebDAV) disabled.'
  desc 'A web server can be installed with functionality that, just by its nature, is not secure. Web Distributed Authoring (WebDAV) is an extension to the HTTP protocol that, when developed, was meant to allow users to create, change, and move documents on a server, typically a web server or web share. Allowing this functionality, development, and deployment is much easier for web authors.

WebDAV is not widely used and has serious security concerns because it may allow clients to modify unauthorized files on the web server.'
  desc 'check', 'Review the web server documentation and deployment configuration to determine if Web Distributed Authoring (WebDAV) is enabled.

If WebDAV is enabled, this is a finding.'
  desc 'fix', 'Configure the web server to disable Web Distributed Authoring.'
  impact 0.5
  ref 'DPMS Target Web Server'
  tag check_id: 'C-6644r377741_chk'
  tag severity: 'medium'
  tag gid: 'V-206383'
  tag rid: 'SV-206383r395853_rule'
  tag stig_id: 'SRG-APP-000141-WSR-000085'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-6644r377742_fix'
  tag 'documentable'
  tag legacy: ['SV-54279', 'V-41702']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
