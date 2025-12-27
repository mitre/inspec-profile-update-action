control 'SV-223890' do
  title 'The CA-TSS PWHIST Control Option must be set to 10 or greater.'
  desc 'Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. If the information system or application allows the user to consecutively reuse their password when that password has exceeded its defined lifetime, the end result is a password that is not changed as per policy requirements.'
  desc 'check', 'From the ISPF Command Shell enter:
TSS MODIFY STATUS

If the PWHIST Control Option value is not set to PWHIST(10) or greater, this is a finding.'
  desc 'fix', 'Evaluate the impact associated with implementation of the control option. Develop a plan of action to implement the following control option setting as specified and proceed with the change.

PWHIST(10) or greater'
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25563r516069_chk'
  tag severity: 'medium'
  tag gid: 'V-223890'
  tag rid: 'SV-223890r561402_rule'
  tag stig_id: 'TSS0-ES-000170'
  tag gtitle: 'SRG-OS-000077-GPOS-00045'
  tag fix_id: 'F-25551r516070_fix'
  tag 'documentable'
  tag legacy: ['SV-107591', 'V-98487']
  tag cci: ['CCI-000200']
  tag nist: ['IA-5 (1) (e)']
end
