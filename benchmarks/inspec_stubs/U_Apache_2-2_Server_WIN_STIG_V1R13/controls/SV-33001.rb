control 'SV-33001' do
  title 'The FollowSymLinks setting must be disabled.'
  desc 'The Options directive configures the web server features that are available in particular directories. The FollowSymLinks option controls the ability of the server to follow symbolic links. A symbolic link allows a file or a directory to be referenced using a symbolic name raising a potential hazard if symbolic linkage is made to a sensitive area. When web scripts are executed and symbolic links are allowed, the web user could be allowed to access locations on the web server that are outside the scope of the web document root or home directory.'
  desc 'check', 'Locate the Apache httpd.conf file.

Open the httpd.conf file with an editor such as notepad, and search for the following uncommented directive: Options

Review all uncommented Options statements for the following value: -FollowSymLinks

If the value is found with an Options statement, and it does not have a preceding “-”, this is a finding.

Notes:
- If the value does NOT exist, this is a finding.
- If all enabled Options statement are set to None this is not a finding.'
  desc 'fix', 'Add a "-" to the FollowSymLinks setting, or set the options directive to None.'
  impact 0.5
  ref 'DPMS Target Apache Instance 2.x'
  tag check_id: 'C-33665r1_chk'
  tag severity: 'medium'
  tag gid: 'V-13732'
  tag rid: 'SV-33001r1_rule'
  tag stig_id: 'WA000-WWA052 W22'
  tag gtitle: 'WA000-WWA052'
  tag fix_id: 'F-29303r1_fix'
  tag 'documentable'
  tag responsibility: 'Web Administrator'
end
