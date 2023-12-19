control 'SV-33020' do
  title 'Each readable web document directory must contain either a default, home, index, or equivalent file.'
  desc 'The goal is to completely control the web users experience in navigating any portion of the web document root directories. Ensuring all web content directories have at least the equivalent of an index.html file is a significant factor to accomplish this end. Also, enumeration techniques, such as URL parameter manipulation, rely upon being able to obtain information about the web server’s directory structure by locating directories with default pages. This practice helps ensure that the anonymous web user will not obtain directory browsing information or an error message that reveals the server type and version.'
  desc 'check', "To view the DocumentRoot value enter the following command: 
awk '{print $1,$2,$3}' /usr/local/apache2/conf/httpd.conf|grep -i DocumentRoot|grep -v '^#'
Note each location following the DocumentRoot string, this is the configured path(s) to the document root directory(s). 
To view a list of the directories and sub-directories and the file index.html, from each stated DocumentRoot location enter the following commands:
find . -type d
find . -type f -name index.html
Review the results for each document root directory and it's subdirectories. If a directory does not contain an index.html or equivalent default document, this is a finding."
  desc 'fix', 'Add a default document to the applicable directories.'
  impact 0.3
  ref 'DPMS Target Apache Site 2.x'
  tag check_id: 'C-33702r1_chk'
  tag severity: 'low'
  tag gid: 'V-2245'
  tag rid: 'SV-33020r1_rule'
  tag stig_id: 'WG170 A22'
  tag gtitle: 'WG170'
  tag fix_id: 'F-29336r1_fix'
  tag 'documentable'
  tag responsibility: 'Web Administrator'
end
