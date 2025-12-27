control 'SV-33136' do
  title 'The web client account access to the content and scripts directories must be limited to read and execute.'
  desc 'Excessive permissions for the anonymous web user account are one of the most common faults contributing to the compromise of a web server. If this user is able to upload and execute files on the web server, the organization or owner of the server will no longer have control of the asset.'
  desc 'check', 'Locate the Apache httpd.conf file.

If unable to locate the file, perform a search of the system to find the location of the file.

Open the httpd.conf file with an editor such as Notepad, and search for the following uncommented directives:  DocumentRoot, Alias, ScriptAlias, & ScriptAliasMatch 

Navigate to the locations specified after each enabled DocumentRoot, Alias, ScriptAlias, & ScriptAliasMatch directives. 
Right click on the file or directory to be examined. Select Properties. Select the “Security” tab. The only accounts listed should be the web administrator, developers, and the account assigned to run the apache server service. 
If accounts that do not need access to these directories are listed, this is a finding. 
If the permissions assigned to the Apache web server service are greater than Read for locations associated with the DocumentRoot and Alias directives, this is a finding.  If the permissions assigned to the Apache web server service are greater than Read & Execute for locations associated with ScriptAlias and ScriptAliasMatch, this is a finding.'
  desc 'fix', 'Assign the appropriate permissions to the applicable directories and files.'
  impact 0.7
  ref 'DPMS Target Apache Site 2.x'
  tag check_id: 'C-33788r1_chk'
  tag severity: 'high'
  tag gid: 'V-2258'
  tag rid: 'SV-33136r1_rule'
  tag stig_id: 'WG290 W22'
  tag gtitle: 'WG290'
  tag fix_id: 'F-29432r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
end
