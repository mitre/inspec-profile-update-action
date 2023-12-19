control 'SV-36641' do
  title 'Anonymous FTP user access to interactive scripts is prohibited.'
  desc 'The directories containing the CGI scripts, such as PERL, must not be accessible to anonymous users via FTP. This applies to all directories that contain scripts that can dynamically produce web pages in an interactive manner (i.e., scripts based upon user-provided input). Such scripts contain information that could be used to compromise a web service, access system resources, or deface a web site.'
  desc 'check', 'Locate the directories containing the CGI scripts. These directories should be language-specific (e.g., PERL, ASP, JS, JSP, etc.). 

Using ls –al, examine the file permissions on the CGI, the cgi-bin, and the cgi-shl directories.

Anonymous FTP users must not have access to these directories.

If the CGI, the cgi-bin, or the cgi-shl directories can be accessed by any group that does not require access, this is a finding.'
  desc 'fix', 'If the CGI, the cgi-bin, or the cgi-shl directories can be accessed via FTP by any group or user that does not require access, remove permissions to such directories for all but the web administrators and the SAs. Ensure that any such access employs an encrypted connection.'
  impact 0.5
  ref 'DPMS Target Apache Site 2.x'
  tag check_id: 'C-29981r1_chk'
  tag severity: 'medium'
  tag gid: 'V-2270'
  tag rid: 'SV-36641r1_rule'
  tag stig_id: 'WG430 A22'
  tag gtitle: 'WG430'
  tag fix_id: 'F-26838r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Web Administrator']
end
