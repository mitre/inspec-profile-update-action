control 'SV-32630' do
  title 'Backup interactive scripts must be removed from the web site.'
  desc 'Copies of backup files will not execute on the server, but they can be read by the anonymous user if special precautions are not taken. Such backup copies contain the same sensitive information as the actual script being executed and, as such, are useful to malicious users. Techniques and systems exist today to search web servers for such files and are able to exploit the information contained in them.'
  desc 'check', 'This check is limited to CGI/interactive content and not static HTML.

Search the IIS Root and Site Directories for the following files: *.bak, *.old, *.temp, *.tmp, *.backup, or ‘copy of...’.

If files with these extensions are found, this is a finding.'
  desc 'fix', 'Remove the backup files from the production web site.'
  impact 0.3
  ref 'DPMS Target IIS Web Site 7'
  tag check_id: 'C-30361r2_chk'
  tag severity: 'low'
  tag gid: 'V-2230'
  tag rid: 'SV-32630r3_rule'
  tag stig_id: 'WG420 IIS7'
  tag gtitle: 'WG420'
  tag fix_id: 'F-29059r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Web Administrator']
end
