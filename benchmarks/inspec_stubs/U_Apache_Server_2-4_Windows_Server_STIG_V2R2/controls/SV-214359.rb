control 'SV-214359' do
  title 'The Apache web server software must be a vendor-supported version.'
  desc 'Many vulnerabilities are associated with older versions of web server software. As hot fixes and patches are issued, these solutions are included in the next version of the server software. Maintaining the web server at a current version makes the efforts of a malicious user to exploit the web service more difficult.'
  desc 'check', %q(Determine the version of the Apache software that is running on the system.

In a command line, navigate to "<'INSTALLED PATH'>\bin". Run "httpd -v" to view the Apache version.

If the version of Apache is not at the following version or higher, this is a finding:

Apache 2.4 (February 2012))
  desc 'fix', 'Install the current version of the web server software and maintain appropriate service packs and patches.'
  impact 0.7
  ref 'DPMS Target Apache Server 2.4 Windows Server'
  tag check_id: 'C-15571r277580_chk'
  tag severity: 'high'
  tag gid: 'V-214359'
  tag rid: 'SV-214359r505936_rule'
  tag stig_id: 'AS24-W1-000960'
  tag gtitle: 'SRG-APP-000516-WSR-000174'
  tag fix_id: 'F-15569r277581_fix'
  tag 'documentable'
  tag legacy: ['SV-102569', 'V-92481']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
