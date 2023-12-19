control 'SV-76949' do
  title 'ColdFusion must transmit only encrypted representations of passwords to the mail server.'
  desc 'Passwords need to be protected at all times, and encryption is the standard method for protecting passwords during transmission.  If passwords are not encrypted, they can be plainly read (i.e., clear text) and easily compromised.

ColdFusion may use username/password to connect to a mail server.  When this authentication method is used, it is important that the credentials be protected when transmitted by being encrypted.  While TLS encryption is the preferred method by DoD, SSL can be used when the mail server does not offer any other method of encryption.'
  desc 'check', 'Within the Administrator Console, navigate to the "Mail" page under the "Server Settings" menu.

If a user name and password are required for authentication and "Enable TLS connection to mail server" is unchecked and "Enable SSL socket connects to mail server" is unchecked, this is a finding.'
  desc 'fix', 'Navigate to the "Mail" page under the "Server Settings" menu.  Enable SSL/TLS by checking "Enable SSL socket connections to mail server" and/or "Enable TLS connection to mail server" options and select the "Submit Changes" button.'
  impact 0.5
  ref 'DPMS Target ColdFusion 11'
  tag check_id: 'C-63263r2_chk'
  tag severity: 'medium'
  tag gid: 'V-62459'
  tag rid: 'SV-76949r1_rule'
  tag stig_id: 'CF11-04-000135'
  tag gtitle: 'SRG-APP-000172-AS-000120'
  tag fix_id: 'F-68379r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000197']
  tag nist: ['IA-5 (1) (c)']
end
