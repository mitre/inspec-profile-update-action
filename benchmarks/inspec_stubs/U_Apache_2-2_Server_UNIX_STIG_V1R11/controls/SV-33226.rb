control 'SV-33226' do
  title 'The web server must be configured to explicitly deny access to the OS root.'
  desc 'The Apache Directory directive allows for directory specific configuration of access controls and many other features and options. One important usage is to create a default deny policy that does not allow access to Operating System directories and files, except for those specifically allowed. This is done, with denying access to the OS root directory. One aspect of Apache, which is occasionally misunderstood, is the feature of default access. That is, unless you take steps to change it, if the server can find its way to a file through normal URL mapping rules, it can and will serve it to clients. Having a default deny is a predominate security principal, and then helps prevent the unintended access, and we do that in this case by denying access to the OS root directory. The Order directive is important as it provides for other Allow directives to override the default deny.'
  desc 'check', 'Enter the following command:

more /usr/local/Apache2.2/conf/httpd.conf.

Review the httpd.conf file and search for the following  directive:

Directory

For every root directory entry (i.e. <Directory />) ensure the following exists; if not, this is a finding.

Order deny,allow
Deny from all

If the statement above is not found in the root directory statement, this is a finding.

If Allow directives are included in the root directory statement, this is a finding.'
  desc 'fix', 'Edit the httpd.conf file and set the root directory directive as follows:

Directory
Order deny,allow
Deny from all'
  impact 0.5
  ref 'DPMS Target Apache Instance 2.x'
  tag check_id: 'C-33779r1_chk'
  tag severity: 'medium'
  tag gid: 'V-26323'
  tag rid: 'SV-33226r1_rule'
  tag stig_id: 'WA00540 A22'
  tag gtitle: 'WA00540'
  tag fix_id: 'F-29418r1_fix'
  tag 'documentable'
  tag responsibility: 'Web Administrator'
end
