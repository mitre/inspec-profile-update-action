control 'SV-214410' do
  title 'All IIS 8.5 web server sample code, example applications, and tutorials must be removed from a production IIS 8.5 server.'
  desc 'Web server documentation, sample code, example applications, and tutorials may be an exploitable threat to a web server. A production web server may only contain components that are operationally necessary (i.e., compiled code, scripts, web content, etc.). Delete all directories containing samples and any scripts used to execute the samples.'
  desc 'check', 'Navigate to the following folders:

inetpub\\
Program Files\\Common Files\\System\\msadc
Program Files (x86)\\Common Files\\System\\msadc

If the folder or sub-folders contain any executable sample code, example applications, or tutorials which are not explicitly used by a production website, this is a finding.'
  desc 'fix', 'Remove any executable sample code, example applications, or tutorials which are not explicitly used by a production website.'
  impact 0.7
  ref 'DPMS Target Microsoft IIS 8.5 Server'
  tag check_id: 'C-15620r310278_chk'
  tag severity: 'high'
  tag gid: 'V-214410'
  tag rid: 'SV-214410r879587_rule'
  tag stig_id: 'IISW-SV-000120'
  tag gtitle: 'SRG-APP-000141-WSR-000077'
  tag fix_id: 'F-15618r310279_fix'
  tag 'documentable'
  tag legacy: ['SV-91401', 'V-76705']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
