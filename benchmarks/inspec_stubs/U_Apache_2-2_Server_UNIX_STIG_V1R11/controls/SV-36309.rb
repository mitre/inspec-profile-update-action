control 'SV-36309' do
  title 'MIME types for csh or sh shell programs must be disabled.'
  desc "Users must not be allowed to access the shell programs. Shell programs might execute shell escapes and could then perform unauthorized activities that could damage the security posture of the web server. A shell is a program that serves as the basic interface between the user and the operating system. In this regard, there are shells that are security risks in the context of a web server and shells that are unauthorized in the context of the Security Features User's Guide."
  desc 'check', 'Enter the following commands: 

grep "Action" /usr/local/apache2/conf/httpd.conf grep "AddHandler" /usr/local/apache2/conf/httpd.conf 

If either of these exist and they configure /bin/csh, or any other shell as a viewer for documents, this is a finding.'
  desc 'fix', 'Disable MIME types for csh or sh shell programs.'
  impact 0.5
  ref 'DPMS Target Apache Instance 2.x'
  tag check_id: 'C-31107r2_chk'
  tag severity: 'medium'
  tag gid: 'V-2225'
  tag rid: 'SV-36309r2_rule'
  tag stig_id: 'WG370 A22'
  tag gtitle: 'WG370'
  tag fix_id: 'F-26772r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Web Administrator']
end
