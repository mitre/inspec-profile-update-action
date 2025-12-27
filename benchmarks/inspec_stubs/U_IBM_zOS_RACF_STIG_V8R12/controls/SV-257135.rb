control 'SV-257135' do
  title 'IBM Passtickets must be configured to be KeyEncrypted.'
  desc 'Passwords such as IBM Passtickets need to be protected at all times, and encryption is the standard method for protecting such passwords. If passwords are not encrypted, they may be plainly read (i.e., clear text) and easily compromised.'
  desc 'check', 'From the ISPF Command Shell enter:

RList PTKTDATA * SSIGNON NORACF

If any profile is not defined as KEYENCRYPTED, this is a finding.'
  desc 'fix', 'Ensure that all Passticket profiles are configured to be KeyEncrypted.'
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-60820r904389_chk'
  tag severity: 'medium'
  tag gid: 'V-257135'
  tag rid: 'SV-257135r904403_rule'
  tag stig_id: 'RACF-ES-000860'
  tag gtitle: 'SRG-OS-000073-GPOS-00041'
  tag fix_id: 'F-60761r904390_fix'
  tag 'documentable'
  tag cci: ['CCI-000196']
  tag nist: ['IA-5 (1) (c)']
end
