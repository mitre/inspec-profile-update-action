control 'SV-33107' do
  title 'Each readable web document directory must contain either a default, home, index, or equivalent file.'
  desc 'The goal is to completely control the web users experience in navigating any portion of the web document root directories. Ensuring all web content directories have indexing turned off or at least the equivalent of an index.html file is a significant factor to accomplish this end. Enumeration techniques, such as URL parameter manipulation, rely upon the ability to obtain information about the web server’s directory structure through locating directories without default pages.'
  desc 'check', 'Locate the Apache httpd.conf file.

If unable to locate the file, perform a search of the system to find the location of the file.

Open the httpd.conf file with an editor such as notepad, and search for the following uncommented directive: DocumentRoot

Note the name of the DocumentRoot directory.

Review the results for each document root directory and its subdirectories. If a directory does not contain an index.html or equivalent default document, this is a finding.'
  desc 'fix', 'Add a default document to the applicable directories.'
  impact 0.3
  ref 'DPMS Target Apache Site 2.0'
  tag check_id: 'C-33768r1_chk'
  tag severity: 'low'
  tag gid: 'V-2245'
  tag rid: 'SV-33107r1_rule'
  tag stig_id: 'WG170 W22'
  tag gtitle: 'WG170'
  tag fix_id: 'F-29405r1_fix'
  tag 'documentable'
  tag responsibility: 'Web Administrator'
  tag ia_controls: 'ECAN-1, ECSC-1'
end
