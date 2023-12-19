control 'SV-33108' do
  title 'The web document (home) directory must be in a separate partition from the web server’s system files.'
  desc 'Application partitioning enables an additional security measure by securing user traffic under one security context, while managing system and application files under another. Web content is accessible to an anonymous web user. For such an account to have access to system files of any type is a major security risk that is avoidable and desirable. Failure to partition the system files from the web site documents increases risk of attack via directory traversal, or impede web site availability due to drive space exhaustion.'
  desc 'check', 'Verify that installation directories for Apache HTTP server are located on another partition, other than the OS partition.

Locate the Apache httpd.conf file.

If unable to locate the file, perform a search of the system to find the location of the file.

Open the httpd.conf file with an editor such as notepad, and search for the following uncommented directives: DocumentRoot, ErrorLog, CustomLog 

Note the location specified for each of the directives. 

If the path for any of the directives is on the same partition as the web server operating system files, this is a finding.'
  desc 'fix', 'Move the web server system files including the web document root (home) and log directories to a separate partition, other than the OS partition.'
  impact 0.5
  ref 'DPMS Target Apache Site 2.0'
  tag check_id: 'C-33769r1_chk'
  tag severity: 'medium'
  tag gid: 'V-3333'
  tag rid: 'SV-33108r1_rule'
  tag stig_id: 'WG205 W22'
  tag gtitle: 'WG205'
  tag fix_id: 'F-29406r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'DCPA-1'
end
