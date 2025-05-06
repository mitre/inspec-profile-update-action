control 'SV-33092' do
  title 'Backup interactive scripts on the production web server must be prohibited.'
  desc 'Copies of backup files will not execute on the server, but can be read by the anonymous user if special precautions are not taken. Such backup copies contain the same sensitive information as the actual script being executed and as such are useful to malicious users. Techniques and systems exist today which search web servers for such files and are able to exploit the information contained in them. Backup copies of files are automatically created by some text editors such as emacs and edit plus. Having backup scripts on the web server provides one more opportunities for malicious persons to view these scripts and use information found in them.'
  desc 'check', 'This check is limited to CGI/interactive content and not static HTML.

Find on all hard drives files containing the following extensions: *.bak, *.old, *.temp, *.tmp, or *.backup.

If files with these extensions are found in either the document directory or the home directory of the web server, this is a finding.

If files with these extensions are stored in a repository (not in the document root) as backups for the web server, this is a finding. 

If files with these extensions have no relationship with web activity, such as a backup batch file for operating system utility, and they are not accessible by the web application, this is not a finding.'
  desc 'fix', 'Ensure that CGI backup scripts are not left on the production web server.'
  impact 0.3
  ref 'DPMS Target Apache Instance 2.0'
  tag check_id: 'C-33758r1_chk'
  tag severity: 'low'
  tag gid: 'V-2230'
  tag rid: 'SV-33092r1_rule'
  tag stig_id: 'WG420 W22'
  tag gtitle: 'WG420'
  tag fix_id: 'F-29394r1_fix'
  tag 'documentable'
  tag responsibility: 'Web Administrator'
  tag ia_controls: 'ECSC-1'
end
