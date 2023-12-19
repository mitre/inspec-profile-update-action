control 'SV-202065' do
  title 'The network device must transmit only encrypted representations of passwords.'
  desc 'Passwords need to be protected at all times, and encryption is the standard method for protecting passwords. If passwords are not encrypted, they can be plainly read (i.e., clear text) and easily compromised.

Network devices can accomplish this by making direct function calls to encryption modules or by leveraging operating system encryption capabilities.'
  desc 'check', 'Determine if the network device or its associated authentication server transmits only encrypted representations of passwords.  This requirement may be verified by demonstration or configuration review. If the network device or the associated authentication server transmits unencrypted representations of passwords, this is a finding.'
  desc 'fix', 'Configure the network device or its associated authentication server to transmit only encrypted representations of passwords.'
  impact 0.7
  ref 'DPMS Target Network Device Management'
  tag check_id: 'C-2191r381830_chk'
  tag severity: 'high'
  tag gid: 'V-202065'
  tag rid: 'SV-202065r879609_rule'
  tag stig_id: 'SRG-APP-000172-NDM-000259'
  tag gtitle: 'SRG-APP-000172'
  tag fix_id: 'F-2192r381831_fix'
  tag 'documentable'
  tag legacy: ['SV-69379', 'V-55133']
  tag cci: ['CCI-000197']
  tag nist: ['IA-5 (1) (c)']
end
