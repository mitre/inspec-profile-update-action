control 'SV-240240' do
  title 'Lighttpd must have MIME types for csh or sh shell programs disabled.'
  desc "Users must not be allowed to access the shell programs. Shell programs might execute shell escapes and could then perform unauthorized activities that could damage the security posture of the web server. A shell is a program that serves as the basic interface between the user and the operating system. In this regard, there are shells that are security risks in the context of a web server and shells that are unauthorized in the context of the Security Features User's Guide.

Lighttpd must be configured to disable MIME types for csh or sh shell programs."
  desc 'check', %q(At the command prompt, execute the following command:

cat /opt/vmware/etc/lighttpd/lighttpd.conf | egrep '".sh"|".csh"'

If the command returns any value, this is a finding.)
  desc 'fix', 'Navigate to and open /opt/vmware/etc/lighttpd/lighttpd.conf

Delete any line(s) that return the value of csh or sh.'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x Lighttpd'
  tag check_id: 'C-43473r667895_chk'
  tag severity: 'medium'
  tag gid: 'V-240240'
  tag rid: 'SV-240240r879587_rule'
  tag stig_id: 'VRAU-LI-000185'
  tag gtitle: 'SRG-APP-000141-WSR-000081'
  tag fix_id: 'F-43432r667896_fix'
  tag 'documentable'
  tag legacy: ['SV-99911', 'V-89261']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
