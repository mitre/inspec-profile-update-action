control 'SV-14278' do
  title 'Remote authors or content providers will only use secure encrypted logons and connections to upload files to the Document Root directory.'
  desc 'Logging in to a web server via a telnet session or using HTTP or FTP in order to upload documents to the web site is a risk if proper encryption is not utilized to protect the data being transmitted. A secure shell service or HTTPS needs to be installed and in use for these purposes.'
  desc 'check', 'Query the SA to determine if there is a process for the uploading of files to the web site. 

This process should include the requirement for the use of a secure encrypted logon and secure encrypted connection.

If the remote users are uploading files without utilizing approved encryption methods, this is a finding.'
  desc 'fix', 'Use only secure encrypted logons and connections for uploading files to the web site.'
  impact 0.7
  ref 'DPMS Target IIS Web Site 7'
  tag check_id: 'C-30006r1_chk'
  tag severity: 'high'
  tag gid: 'V-13686'
  tag rid: 'SV-14278r2_rule'
  tag stig_id: 'WG235'
  tag gtitle: 'WG235'
  tag fix_id: 'F-26857r1_fix'
  tag 'documentable'
  tag responsibility: 'Web Administrator'
end
