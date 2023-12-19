control 'SV-6930' do
  title 'Backup interactive scripts on the production web server are prohibited.'
  desc 'Copies of backup files will not execute on the server, but they can be read by the anonymous user if special precautions are not taken. Such backup copies contain the same sensitive information as the actual script being executed and, as such, are useful to malicious users. Techniques and systems exist today that search web servers for such files and are able to exploit the information contained in them. 

Backup copies of files are automatically created by some text editors such as emacs and edit plus. The emacs editor will write a backup file with an extension ~ added to the name of the original file. The edit plus editor will create a .bak file. Of course, this would imply the presence and use of development tools on the web server, which is a finding under WG130. Having backup scripts on the web server provides one more opportunity for malicious persons to view these scripts and use the information found in them.'
  desc 'check', 'This check is limited to CGI/interactive content and not static HTML.

Search for backup copies of CGI scripts on the web server or ask the SA or the Web Administrator if they keep backup copies of CGI scripts on the web server. 

Common backup file extensions are: *.bak, *.old, *.temp, *.tmp, *.backup, *.??0. This would also apply to .jsp files. 

UNIX: 
find / name “*.bak” –print
find / name “*.*~” –print
find / name “*.old” –print 

If files with these extensions are found in either the document directory or the home directory of the web server, this is a finding. 

If files with these extensions are stored in a repository (not in the document root) as backups for the web server, this is a finding.

If files with these extensions have no relationship with web activity, such as a backup batch file for operating system utility, and they are not accessible by the web application, this is not a finding.'
  desc 'fix', 'Ensure that CGI backup scripts are not left on the production web server.'
  impact 0.3
  ref 'DPMS Target Apache Instance 2.0'
  tag check_id: 'C-30362r1_chk'
  tag severity: 'low'
  tag gid: 'V-2230'
  tag rid: 'SV-6930r1_rule'
  tag stig_id: 'WG420 A22'
  tag gtitle: 'WG420'
  tag fix_id: 'F-27282r1_fix'
  tag 'documentable'
  tag responsibility: ['Web Administrator', 'System Administrator']
  tag ia_controls: 'ECSC-1'
end
