control 'SV-218781' do
  title 'Backup interactive scripts on the IIS 10.0 server must be removed.'
  desc 'Copies of backup files will not execute on the server, but they can be read by the anonymous user if special precautions are not taken. Such backup copies contain the same sensitive information as the actual script being executed and, as such, are useful to malicious users. Techniques and systems exist today to search web servers for such files and are able to exploit the information contained in them.'
  desc 'check', 'Determine whether scripts are used on the web server for the subject website. Common file extensions include, but are not limited to: .cgi, .pl, .vb, .class, .c, .php, .asp, and .aspx. The scope of this requirement is to analyze only within the web server content directories, not the entire underlying operating system.

If the website does not utilize CGI, this finding is Not Applicable.

Open the IIS 10.0 Manager.

Right-click the IIS 10.0 web site name and select "Explore".

Search for the listed script extensions

Search for the following files: *.bak, *.old, *.temp, *.tmp, *.backup, or “copy of...”.

If files with these extensions are found, this is a finding.'
  desc 'fix', 'Remove the backup files from the production web server.'
  impact 0.5
  ref 'DPMS Target Microsoft IIS 10.0 Site'
  tag check_id: 'C-20254r311241_chk'
  tag severity: 'medium'
  tag gid: 'V-218781'
  tag rid: 'SV-218781r879587_rule'
  tag stig_id: 'IIST-SI-000263'
  tag gtitle: 'SRG-APP-000141-WSR-000087'
  tag fix_id: 'F-20252r311242_fix'
  tag 'documentable'
  tag legacy: ['SV-109387', 'V-100283']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
