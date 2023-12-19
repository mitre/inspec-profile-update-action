control 'SV-33021' do
  title 'The web document (home) directory must be in a separate partition from the web server’s system files.'
  desc 'Application partitioning enables an additional security measure by securing user traffic under one security context, while managing system and application files under another.  Web content is can be to an anonymous web user. For such an account to have access to system files of any type is a major security risk that is avoidable and desirable. Failure to partition the system files from the web site documents increases risk of attack via directory traversal, or impede web site availability due to drive space exhaustion.'
  desc 'check', %q(grep "DocumentRoot" /usr/local/apache2/conf/httpd.conf 

Note each location following the DocumentRoot string, this is the configured path to the document root directory(s). 

Use the command df -k to view each document root's partition setup. 

Compare that against the results for the Operating System file systems, and against the partition for the web server system files, which is the result of the command: 

df -k /usr/local/apache2/bin

If the document root path is on the same partition as the web server system files or the OS file systems, this is a finding.)
  desc 'fix', 'Move the web document (normally "htdocs") directory to a separate partition, other than the OS root partition and the web server’s system files.'
  impact 0.5
  ref 'DPMS Target Apache Site 2.x'
  tag check_id: 'C-33703r1_chk'
  tag severity: 'medium'
  tag gid: 'V-3333'
  tag rid: 'SV-33021r1_rule'
  tag stig_id: 'WG205 A22'
  tag gtitle: 'WG205'
  tag fix_id: 'F-29337r1_fix'
  tag 'documentable'
  tag responsibility: 'Web Administrator'
end
