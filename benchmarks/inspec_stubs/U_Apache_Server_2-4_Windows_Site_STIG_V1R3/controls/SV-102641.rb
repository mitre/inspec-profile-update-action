control 'SV-102641' do
  title 'The Apache web server must display a default hosted application web page, not a directory listing, when a requested web page cannot be found.'
  desc %q(The goal is to completely control the web user's experience in navigating any portion of the web document root directories. Ensuring all web content directories have at least the equivalent of an "index.html" file is a significant factor to accomplish this end.

Enumeration techniques, such as URL parameter manipulation, rely upon being able to obtain information about the web server's directory structure by locating directories without default pages. In the scenario, the web server will display to the user a listing of the files in the directory being accessed. By having a default hosted application web page, the anonymous web user will not obtain directory browsing information or an error message that reveals the server type and version.)
  desc 'check', %q(Review the DocumentRoot directive in the <'INSTALLED PATH'>\conf\httpd.conf file.

Note each location following the "DocumentRoot" string. This is the configured path(s) to the document root directory(s).

To view a list of the directories and sub-directories and the file "index.html", from each stated "DocumentRoot" location, enter the following command:

dir "index.html"

Review the results for each document root directory and its subdirectories.

If a directory does not contain an "index.html" or equivalent default document, this is a finding.)
  desc 'fix', 'Add a default document to the applicable directories.'
  impact 0.5
  ref 'DPMS Target Apache Site 2.4 - Windows'
  tag check_id: 'C-91857r1_chk'
  tag severity: 'medium'
  tag gid: 'V-92553'
  tag rid: 'SV-102641r1_rule'
  tag stig_id: 'AS24-W2-000610'
  tag gtitle: 'SRG-APP-000266-WSR-000142'
  tag fix_id: 'F-98795r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']
end
