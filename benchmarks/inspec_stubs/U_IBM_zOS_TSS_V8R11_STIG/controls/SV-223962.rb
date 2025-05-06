control 'SV-223962' do
  title 'CA-TSS ADMINBY Control Option must be set to ADMINBY.'
  desc 'Misuse of privileged functions, either intentionally or unintentionally by authorized users, or by unauthorized external entities that have compromised information system accounts, is a serious and ongoing concern and can have significant adverse impacts on organizations. Auditing the use of privileged functions is one way to detect such misuse and identify the risk from insider threats and the advanced persistent threat.'
  desc 'check', 'From ISPF Command Shell enter:
TSS MODIFY STATUS

If the ADMINBY Control Option value is not set or set to "NOADMBY", this is a finding.'
  desc 'fix', 'Ensure ADMINBY control option is set to "ADMINBY" to record who when and where information in the ACID security record for administrative changes.

Evaluate the impact associated with implementation of the control option. Develop a plan of action to implement the control option setting "ADMINBY" and proceed with the change.'
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25635r516285_chk'
  tag severity: 'medium'
  tag gid: 'V-223962'
  tag rid: 'SV-223962r877803_rule'
  tag stig_id: 'TSS0-ES-000890'
  tag gtitle: 'SRG-OS-000327-GPOS-00127'
  tag fix_id: 'F-25623r516286_fix'
  tag 'documentable'
  tag legacy: ['V-98631', 'SV-107735']
  tag cci: ['CCI-002234']
  tag nist: ['AC-6 (9)']
end
