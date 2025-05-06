control 'SV-206387' do
  title 'The web server must encrypt passwords during transmission.'
  desc 'Data used to authenticate, especially passwords, needs to be protected at all times, and encryption is the standard method for protecting authentication data during transmission. Data used to authenticate can be passed to and from the web server for many reasons. 

Examples include data passed from a user to the web server through an HTTPS connection for authentication, the web server authenticating to a backend database for data retrieval and posting, and the web server authenticating to a clustered web server manager for an update.'
  desc 'check', 'Review the web server documentation and deployed configuration to determine whether passwords are being passed to or from the web server.

If the transmission of passwords is not encrypted, this is a finding.'
  desc 'fix', 'Configure the web server to encrypt the transmission passwords.'
  impact 0.5
  ref 'DPMS Target Web Server'
  tag check_id: 'C-6648r377753_chk'
  tag severity: 'medium'
  tag gid: 'V-206387'
  tag rid: 'SV-206387r879609_rule'
  tag stig_id: 'SRG-APP-000172-WSR-000104'
  tag gtitle: 'SRG-APP-000172'
  tag fix_id: 'F-6648r377754_fix'
  tag 'documentable'
  tag legacy: ['SV-54315', 'V-41738']
  tag cci: ['CCI-000197']
  tag nist: ['IA-5 (1) (c)']
end
