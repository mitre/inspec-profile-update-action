control 'SV-237911' do
  title 'CA VM:Secure product Password Encryption (PEF) option must be properly configured to store and transmit cryptographically-protected passwords.'
  desc 'Passwords need to be protected at all times, and encryption is the standard method for protecting passwords. If passwords are not encrypted, they can be plainly read (i.e., clear text) and easily compromised.

'
  desc 'check', 'Examine the "VMXRPI" Config file used for building the current nucleus.

If the "ENCRYP" record is missing, this is a finding.

If the "ENCRYPT" record does not specify "DES3", this is a finding.

If the DES3KEY Record is missing, this is a finding.'
  desc 'fix', 'Configure the "VMXRPI" Config file to include the following records:

ENCRYPT DES3
DES3KEY word1 word2 word3 word4 word5 word6 or
DES3KEY EXIT filename EXEC|TEXT'
  impact 0.7
  ref 'DPMS Target IBM zVM Using CA VMSecure'
  tag check_id: 'C-41121r858955_chk'
  tag severity: 'high'
  tag gid: 'V-237911'
  tag rid: 'SV-237911r858957_rule'
  tag stig_id: 'IBMZ-VM-000480'
  tag gtitle: 'SRG-OS-000073-GPOS-00041'
  tag fix_id: 'F-41080r858956_fix'
  tag satisfies: ['SRG-OS-000073-GPOS-00041', 'SRG-OS-000074-GPOS-00042']
  tag 'documentable'
  tag legacy: ['SV-93575', 'V-78869']
  tag cci: ['CCI-000196', 'CCI-000197']
  tag nist: ['IA-5 (1) (c)', 'IA-5 (1) (c)']
end
