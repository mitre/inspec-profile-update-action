control 'SV-82875' do
  title 'The Mainframe Product must store only cryptographically protected passwords.'
  desc 'Passwords need to be protected at all times and encryption is the standard method for protecting passwords. If passwords are not encrypted, they can be plainly read (i.e., clear text) and easily compromised.

Applications must enforce password encryption when storing passwords.'
  desc 'check', 'If the Mainframe Product employs an external security manager (ESM) for all account management functions, this is not applicable.

Examine user account management configurations. 

If the Mainframe Product account management configuration does not require that only cryptographically protected passwords are stored, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product account management to store only cryptographically protected passwords.'
  impact 0.5
  ref 'DPMS Target SRG-APP-MFPR'
  tag check_id: 'C-68915r1_chk'
  tag severity: 'medium'
  tag gid: 'V-68385'
  tag rid: 'SV-82875r1_rule'
  tag stig_id: 'SRG-APP-000171-MFP-000233'
  tag gtitle: 'SRG-APP-000171-MFP-000233'
  tag fix_id: 'F-74499r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000196']
  tag nist: ['IA-5 (1) (c)']
end
