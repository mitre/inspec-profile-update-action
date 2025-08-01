control 'SV-214273' do
  title 'The Apache web server software must be a vendor-supported version.'
  desc 'Many vulnerabilities are associated with older versions of web server software. As hot fixes and patches are issued, these solutions are included in the next version of the server software. Maintaining the web server at a current version makes the efforts of a malicious user to exploit the web service more difficult.'
  desc 'check', "Determine the version of the Apache software that is running on the system by entering the following command:

httpd -v

If the version of Apache is not at the following version or higher, this is a finding:

Apache 2.4 (February 2012)

NOTE: In some situations, the Apache software that is being used is supported by another vendor, such as Oracle in the case of the Oracle Application Server or IBM's HTTP Server. The versions of the software in these cases may not match the version number noted above. If the site can provide vendor documentation showing the version of the web server is supported, this would not be a finding."
  desc 'fix', 'Install the current version of the web server software and maintain appropriate service packs and patches.'
  impact 0.7
  ref 'DPMS Target Apache Server 2.4 UNIX Server'
  tag check_id: 'C-15487r277079_chk'
  tag severity: 'high'
  tag gid: 'V-214273'
  tag rid: 'SV-214273r879887_rule'
  tag stig_id: 'AS24-U1-000960'
  tag gtitle: 'SRG-APP-000516-WSR-000174'
  tag fix_id: 'F-15485r277080_fix'
  tag 'documentable'
  tag legacy: ['V-92755', 'SV-102843']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
