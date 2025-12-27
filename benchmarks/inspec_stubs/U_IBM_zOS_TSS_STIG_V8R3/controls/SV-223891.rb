control 'SV-223891' do
  title 'The CA-TSS PPHIST Control Option must be properly set.'
  desc 'Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. If the information system or application allows the user to consecutively reuse their password when that password has exceeded its defined lifetime, the end result is a password that is not changed as per policy requirements.'
  desc 'check', 'From the ISPF Command Shell enter:
TSS MODIFY STATUS

If the PPHIST Control Option conforms to the following requirements, this is not a finding.

PPHIST(10-64)'
  desc 'fix', 'Configure the PPHIST Control Option value to conforms to the following requirements:

PPHIST(10-64)

Example:

TSS MODIFY PPHIST(10)'
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25564r516072_chk'
  tag severity: 'medium'
  tag gid: 'V-223891'
  tag rid: 'SV-223891r561402_rule'
  tag stig_id: 'TSS0-ES-000180'
  tag gtitle: 'SRG-OS-000077-GPOS-00045'
  tag fix_id: 'F-25552r516073_fix'
  tag 'documentable'
  tag legacy: ['SV-107593', 'V-98489']
  tag cci: ['CCI-000200']
  tag nist: ['IA-5 (1) (e)']
end
