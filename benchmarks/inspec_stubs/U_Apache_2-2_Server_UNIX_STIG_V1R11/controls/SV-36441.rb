control 'SV-36441' do
  title 'Web server software must be a vendor-supported version.'
  desc 'Many vulnerabilities are associated with older versions of web server software. As hot fixes and patches are issued, these solutions are included in the next version of the server software. Maintaining the web server at a current version makes the efforts of a malicious user to exploit the web service more difficult.'
  desc 'check', 'To determine the version of the Apache software that is running on the system. Use the command:

httpd –v

httpd2 –v

If the version of Apache is not at the following version or higher, this is a finding.

Apache httpd server version 2.2 - Release 2.2.31 (July 2015)

Note: In some situations, the Apache software that is being used is supported by another vendor, such as Oracle in the case of the Oracle Application Server or IBMs HTTP Server. 
The versions of the software in these cases may not match the above mentioned version numbers. If the site can provide vendor documentation showing the version of the web server is supported, this would not be a finding.'
  desc 'fix', 'Install the current version of the web server software and maintain appropriate service packs and patches.'
  impact 0.7
  ref 'DPMS Target Apache Instance 2.x'
  tag check_id: 'C-29915r5_chk'
  tag severity: 'high'
  tag gid: 'V-2246'
  tag rid: 'SV-36441r2_rule'
  tag stig_id: 'WG190 A22'
  tag gtitle: 'WG190'
  tag fix_id: 'F-2295r5_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Web Administrator']
end
