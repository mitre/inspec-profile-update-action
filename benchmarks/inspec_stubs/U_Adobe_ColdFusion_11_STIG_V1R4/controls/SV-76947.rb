control 'SV-76947' do
  title 'The ColdFusion Administrator Console must transmit only encrypted representations of passwords.'
  desc 'Passwords need to be protected at all times, and encryption is the standard method for protecting passwords during transmission.  If passwords are not encrypted, they can be plainly read (i.e., clear text) and easily compromised.

ColdFusion uses username and password for users to authenticate to the Administrator Console.  When these credentials are sent in plaintext, an attacker can capture the information and use the credentials to log on to the console, creating objects, connections, and accounts for later use.  The attacker will also have access to information stored for connections to other systems that ColdFusion may be connected to for data retrieval.'
  desc 'check', 'Access the Administrator Console through a web browser.  Look for indications that the communication is an https session through the prefix of https on the url and/or the lock icon, depending on the browser in use.

If https does not appear to be in use, this is a finding.'
  desc 'fix', 'Review the documentation for the web server where the Administrator Console is being hosted and setup https encryption to protect passwords during the authentication process.'
  impact 0.5
  ref 'DPMS Target ColdFusion 11'
  tag check_id: 'C-63261r1_chk'
  tag severity: 'medium'
  tag gid: 'V-62457'
  tag rid: 'SV-76947r1_rule'
  tag stig_id: 'CF11-04-000134'
  tag gtitle: 'SRG-APP-000172-AS-000120'
  tag fix_id: 'F-68377r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000197']
  tag nist: ['IA-5 (1) (c)']
end
