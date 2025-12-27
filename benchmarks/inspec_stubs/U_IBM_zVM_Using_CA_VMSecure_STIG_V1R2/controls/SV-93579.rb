control 'SV-93579' do
  title 'CA VM:Secure product PASSWORD user exit must be coded with the PWLIST option properly set.'
  desc 'Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. If the information system or application allows the user to consecutively reuse their password when that password has exceeded its defined lifetime, the end result is a password that is not changed as per policy requirements.'
  desc 'check', 'If there is no CA VM:Secure Product PASSWORD user exit in use, this is a finding.

Examine the CA VM:Secure product PASSWORD user exit for requirement that uses a “PWLIST” option that prohibits password reuse for five generations.

If this code is missing, this is a finding.'
  desc 'fix', 'Engineer code in the CA VM:Secure Product PASSWORD user exit that uses a “PWLIST” that prohibits password reuse for five generations.'
  impact 0.5
  ref 'DPMS Target z/VM Using CA VM:Secure'
  tag check_id: 'C-78459r1_chk'
  tag severity: 'medium'
  tag gid: 'V-78873'
  tag rid: 'SV-93579r1_rule'
  tag stig_id: 'IBMZ-VM-000510'
  tag gtitle: 'SRG-OS-000077-GPOS-00045'
  tag fix_id: 'F-85623r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000200']
  tag nist: ['IA-5 (1) (e)']
end
