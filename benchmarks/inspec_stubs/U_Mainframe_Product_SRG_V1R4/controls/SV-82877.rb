control 'SV-82877' do
  title 'The Mainframe Product must transmit only cryptographically protected passwords.'
  desc 'Passwords need to be protected at all times and encryption is the standard method for protecting passwords. If passwords are not encrypted, they can be plainly read (i.e., clear text) and easily compromised.

Applications can accomplish this by making direct function calls to encryption modules or by leveraging operating system encryption capabilities.'
  desc 'check', 'If the Mainframe Product employs an external security manager (ESM) for all account management functions, this is not applicable.

Examine user account management configurations. 

If the Mainframe Product account management configuration does not require transmittal of only cryptographically protected passwords, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product account management to transmit only cryptographically protected passwords.'
  impact 0.5
  ref 'DPMS Target SRG-APP-MFPR'
  tag check_id: 'C-68917r1_chk'
  tag severity: 'medium'
  tag gid: 'V-68387'
  tag rid: 'SV-82877r1_rule'
  tag stig_id: 'SRG-APP-000172-MFP-000234'
  tag gtitle: 'SRG-APP-000172-MFP-000234'
  tag fix_id: 'F-74501r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000197']
  tag nist: ['IA-5 (1) (c)']
end
