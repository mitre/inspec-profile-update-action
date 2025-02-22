control 'SV-36644' do
  title 'All interactive programs must be placed in a designated directory with appropriate permissions.'
  desc 'CGI scripts represents one of the most common and exploitable means of compromising a web server. By definition, CGI are executable by the operating system of the host server. While access control is provided via the web service, the execution of CGI programs is not otherwise limited unless the SA or Web Manager takes specific measures. CGI programs can access and alter data files, launch other programs and use the network. CGI programs can be written in any available programming language. C, PERL, PHP, Javascript, VBScript and shell (sh, ksh, bash) are popular choices.'
  desc 'check', 'To preclude access to the servers root directory, ensure the following directive is in the httpd.conf file. This entry will also stop users from setting up .htaccess files which can override security features configured in httpd.conf.

<DIRECTORY /[website root dir]>
AllowOverride None
</DIRECTORY>

If the AllowOverride None is not set, this is a finding.'
  desc 'fix', 'Enter the statement above into httpd.conf file for all web site root directories.'
  impact 0.5
  ref 'DPMS Target Apache Site 2.0'
  tag check_id: 'C-35736r1_chk'
  tag severity: 'medium'
  tag gid: 'V-2228'
  tag rid: 'SV-36644r1_rule'
  tag stig_id: 'WG400 W22'
  tag gtitle: 'WG400'
  tag fix_id: 'F-30977r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'DCPA-1'
end
