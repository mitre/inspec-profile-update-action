control 'SV-221465' do
  title 'OHS must prohibit anonymous FTP user access to interactive scripts.'
  desc 'The directories containing the CGI scripts, such as PERL, must not be accessible to anonymous users via FTP. This applies to all directories that contain scripts that can dynamically produce web pages in an interactive manner (i.e., scripts based upon user-provided input). Such scripts contain information that could be used to compromise a web service, access system resources, or deface a web site.'
  desc 'check', '1. Check that all ftp access is authenticated, authorized, and secure.

2. If not, this is a finding.'
  desc 'fix', 'Ensure that all file transfers to the server are authenticated, authorized, and secure.'
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server 12.1.3'
  tag check_id: 'C-23180r415078_chk'
  tag severity: 'medium'
  tag gid: 'V-221465'
  tag rid: 'SV-221465r415080_rule'
  tag stig_id: 'OH12-1X-000228'
  tag gtitle: 'SRG-APP-000516-WSR-000174'
  tag fix_id: 'F-23169r415079_fix'
  tag 'documentable'
  tag legacy: ['SV-79183', 'V-64693']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
