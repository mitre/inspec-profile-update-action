control 'SV-40826' do
  title 'Remote authors or content providers must have all files scanned for malware before uploading files to the Document Root directory.'
  desc 'Remote web authors should not be able to upload files to the DocumentRoot directory structure without virus checking and checking for malicious or mobile code. A remote web user whose agency has a Memorandum of Agreement (MOA) with the hosting agency and has submitted a DoD form 2875 (System Authorization Access Request (SAAR)) or an equivalent document will be allowed to post files to a temporary location on the server. All posted files to this temporary location will be scanned for viruses and content checked for malicious or mobile code. Only files free of viruses and malicious or mobile code will be posted to the appropriate Document Root directory.'
  desc 'check', 'Remote web authors should not be able to upload files to the Document Root directory structure without virus checking and checking for malicious or mobile code. 

Query the SA to determine if there is anti-virus software active on the server with auto-protect enabled, or if there is another process in place for the scanning of files being posted by remote authors. 

If there is no virus software on the system with auto-protect enabled, or if there is not a process in place to ensure all files being posted are being virus scanned before being saved to the document root, this is a finding.'
  desc 'fix', 'Install anti-virus software on the system and set it to automatically scan new files that are introduced to the web server.'
  impact 0.5
  ref 'DPMS Target Apache Instance 2.x'
  tag check_id: 'C-33747r1_chk'
  tag severity: 'medium'
  tag gid: 'V-13687'
  tag rid: 'SV-40826r1_rule'
  tag stig_id: 'WG237 W22'
  tag gtitle: 'WG237'
  tag fix_id: 'F-29382r1_fix'
  tag 'documentable'
  tag responsibility: ['Web Administrator', 'System Administrator']
end
