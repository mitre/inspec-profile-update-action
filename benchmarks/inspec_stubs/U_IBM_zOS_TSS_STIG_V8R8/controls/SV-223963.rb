control 'SV-223963' do
  title 'CA-TSS LOG Control Option must be set to (SMF,INIT, SEC9, MSG).'
  desc 'Misuse of privileged functions, either intentionally or unintentionally by authorized users, or by unauthorized external entities that have compromised information system accounts, is a serious and ongoing concern and can have significant adverse impacts on organizations. Auditing the use of privileged functions is one way to detect such misuse and identify the risk from insider threats and the advanced persistent threat.'
  desc 'check', 'From the ISPF Command Shell enter:
TSS MODIFY STATUS

If the LOG Control Option is NOT set to (SMF,INIT, SEC9, MSG), this is a finding.'
  desc 'fix', 'Evaluate the impact associated with implementation of the control option. Develop a plan of action to implement the control option setting as specified below and proceed with the change.

LOG(SMF,INIT, SEC9, MSG)'
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25636r516288_chk'
  tag severity: 'medium'
  tag gid: 'V-223963'
  tag rid: 'SV-223963r856100_rule'
  tag stig_id: 'TSS0-ES-000900'
  tag gtitle: 'SRG-OS-000327-GPOS-00127'
  tag fix_id: 'F-25624r516289_fix'
  tag 'documentable'
  tag legacy: ['V-98633', 'SV-107737']
  tag cci: ['CCI-002234']
  tag nist: ['AC-6 (9)']
end
