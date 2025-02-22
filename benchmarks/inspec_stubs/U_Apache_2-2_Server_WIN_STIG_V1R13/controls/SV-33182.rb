control 'SV-33182' do
  title 'Web server options for the OS root must be disabled.'
  desc 'The Apache Options directive allows for specific configuration of options, including execution of CGI, following symbolic links, server side includes, and content negotiation. The Options directive for the root OS level is used to create a default minimal options policy that allows only the minimal options at the root directory level. Then for specific web sites or portions of the web site, options may be enabled as needed and appropriate. No options should be enabled and the value for the Options Directive should be None.'
  desc 'check', 'Locate the Apache httpd.conf file.

Open the httpd.conf file with an editor such as notepad, and search for the following uncommented directive: Directory

For every root directory entry (i.e. <Directory />) ensure the following entry exists after it:

Options None

If the statement above is not found in the root directory statement, this is a finding. If Allow directives are included in the root directory statement, this is a finding. If the root directory statement is not found at all, this is a finding.'
  desc 'fix', 'Ensure the Directory directive has the following after it:

Options None'
  impact 0.5
  ref 'DPMS Target Apache Instance 2.x'
  tag check_id: 'C-33814r1_chk'
  tag severity: 'medium'
  tag gid: 'V-26324'
  tag rid: 'SV-33182r1_rule'
  tag stig_id: 'WA00545 W22'
  tag gtitle: 'WA00545'
  tag fix_id: 'F-29466r1_fix'
  tag 'documentable'
  tag responsibility: 'Web Administrator'
end
