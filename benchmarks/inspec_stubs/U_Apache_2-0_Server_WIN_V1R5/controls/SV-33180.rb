control 'SV-33180' do
  title 'The web server must be configured to explicitly deny access to the OS root.'
  desc 'The Apache Directory directive allows for directory specific configuration of access controls and many other features and options. One important usage is to create a default deny policy that does not allow access to Operating System directories and files, except for those specifically allowed. This is done, with denying access to the OS root directory. One aspect of Apache, which is occasionally misunderstood, is the feature of default access. That is, unless you take steps to change it, if the server can find its way to a file through normal URL mapping rules, it can and will serve it to clients. Having a default deny is a predominate security principal, and then helps prevent the unintended access, and we do that in this case by denying access to the OS root directory. The Order directive is important as it provides for other Allow directives to override the default deny.'
  desc 'check', "Locate the Apache httpd.conf file.

Open the httpd.conf file with an editor such as notepad, and search for the following uncommented directive: Directory

For every root directory entry (i.e. <Directory />) ensure the following exists after it:

Order deny,allow
Deny from all

If the statement above is not found in the root directory statement, this is a finding. If Allow directives are included in the root directory statement, this is a finding. If the root directory statement isn't found at all, this is a finding."
  desc 'fix', 'Add the following after the root directory directive:

Order deny,allow
Deny from all'
  impact 0.5
  ref 'DPMS Target Apache Instance 2.0'
  tag check_id: 'C-33813r1_chk'
  tag severity: 'medium'
  tag gid: 'V-26323'
  tag rid: 'SV-33180r1_rule'
  tag stig_id: 'WA00540 W22'
  tag gtitle: 'WA00540'
  tag fix_id: 'F-29465r1_fix'
  tag 'documentable'
  tag responsibility: 'Web Administrator'
  tag ia_controls: 'IAIA-1, IAIA-2'
end
