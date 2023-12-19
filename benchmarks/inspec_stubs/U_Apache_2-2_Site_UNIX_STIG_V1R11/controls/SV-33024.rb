control 'SV-33024' do
  title 'Web Administrators must only use encrypted connections for Document Root directory uploads.'
  desc 'Logging in to a web server via an unencrypted protocol or service, to upload documents to the web site, is a risk if proper encryption is not utilized to protect the data being transmitted.  An encrypted protocol or service must be used for remote access to web administration tasks.'
  desc 'check', 'Determine if there is a process for the uploading of files to the web site. This process should include the requirement for the use of a secure encrypted logon and secure encrypted connection. If the remote users are uploading files without utilizing approved encryption methods, this is a finding.'
  desc 'fix', 'Use only secure encrypted logons and connections for uploading files to the web site.'
  impact 0.7
  ref 'DPMS Target Apache Site 2.x'
  tag check_id: 'C-33706r1_chk'
  tag severity: 'high'
  tag gid: 'V-13686'
  tag rid: 'SV-33024r1_rule'
  tag stig_id: 'WG235 A22'
  tag gtitle: 'WG235'
  tag fix_id: 'F-29338r1_fix'
  tag 'documentable'
  tag responsibility: 'Web Administrator'
end
