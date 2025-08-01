control 'SV-221468' do
  title 'Remote authors or content providers must have all files scanned for viruses and malicious code before uploading files to the Document Root directory.'
  desc 'Remote web authors should not be able to upload files to the DocumentRoot directory structure without virus checking and checking for malicious or mobile code. A remote web user whose agency has a Memorandum of Agreement (MOA) with the hosting agency and has submitted a DoD form 2875 (System Authorization Access Request (SAAR)) or an equivalent document will be allowed to post files to a temporary location on the server. All posted files to this temporary location will be scanned for viruses and content checked for malicious or mobile code. Only files free of viruses and malicious or mobile code will be posted to the appropriate Document Root directory.'
  desc 'check', '1. Check that any files uploaded to the OHS environment are checked for viruses, malicious code, and mobile code.

2. If there is not anti-virus software on the system with auto-protect enabled or if there is not a process in place to ensure all files being posted to the OHS sites are being scanned, this is a finding.'
  desc 'fix', 'Install anti-virus software on the OHS server and configure it to automatically scan for any viruses, malicious code, and mobile code.'
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server 12.1.3'
  tag check_id: 'C-23183r415087_chk'
  tag severity: 'medium'
  tag gid: 'V-221468'
  tag rid: 'SV-221468r879887_rule'
  tag stig_id: 'OH12-1X-000231'
  tag gtitle: 'SRG-APP-000516-WSR-000174'
  tag fix_id: 'F-23172r415088_fix'
  tag 'documentable'
  tag legacy: ['SV-79189', 'V-64699']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
