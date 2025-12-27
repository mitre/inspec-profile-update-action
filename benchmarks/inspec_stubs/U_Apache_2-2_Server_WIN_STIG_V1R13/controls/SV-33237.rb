control 'SV-33237' do
  title 'The ability to override the access configuration for the OS root directory must be disabled.'
  desc 'The Apache OverRide directive allows for .htaccess files to be used to override much of the configuration, including authentication, handling of document types, auto generated indexes, access control, and options. When the server finds an .htaccess file (as specified by AccessFileName) it needs to know which directives declared in that file can override earlier access information. When this directive is set to None, then .htaccess files are completely ignored. In this case, the server will not even attempt to read .htaccess files in the file system. When this directive is set to All, then any directive which has the .htaccess Context is allowed in .htaccess files.'
  desc 'check', 'Locate the Apache httpd.conf file.

Open the httpd.conf file with an editor such as notepad, and search for the following uncommented directive: Directory

For every root directory entry (i.e. <Directory />) ensure the following entry exists after it:

AllowOverride None

If the statement above is not found in the root directory statement, this is a finding. If Allow directives are included in the root directory statement, this is a finding. If the root directory statement is not found at all, this is a finding.'
  desc 'fix', 'Add the following after the Directory directive:

AllowOverride None'
  impact 0.5
  ref 'DPMS Target Apache Instance 2.x'
  tag check_id: 'C-33834r1_chk'
  tag severity: 'medium'
  tag gid: 'V-26393'
  tag rid: 'SV-33237r1_rule'
  tag stig_id: 'WA00547 W22'
  tag gtitle: 'WA00547'
  tag fix_id: 'F-29500r1_fix'
  tag 'documentable'
  tag responsibility: 'Web Administrator'
end
