control 'SV-77639' do
  title 'The system must prohibit password reuse for a minimum of five generations.'
  desc 'Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. 

To meet password policy requirements, passwords need to be changed at specific policy-based intervals. 

If the information system or application allows the user to consecutively reuse their password when that password has exceeded its defined lifetime, the end result is a password that is not changed as per policy requirements.'
  desc 'check', 'From the vSphere Web Client go to Administration >> Single Sign-On >> Configuration >> Policies >> Password Policy.  View the value of the "Restrict reuse" setting.

If the "Restrict reuse" policy is not set to 5 or more, this is a finding.'
  desc 'fix', 'From the vSphere Web Client go to Administration >> Single Sign-On >> Configuration >> Policies >> Password Policy.

Click "Edit" and enter "5" into the "Restrict reuse" setting and click "OK".'
  impact 0.5
  ref 'DPMS Target vCenter Server 6.0'
  tag check_id: 'C-63901r2_chk'
  tag severity: 'medium'
  tag gid: 'V-63149'
  tag rid: 'SV-77639r1_rule'
  tag stig_id: 'VCWN-06-000001'
  tag gtitle: 'SRG-APP-000165'
  tag fix_id: 'F-69067r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000200']
  tag nist: ['IA-5 (1) (e)']
end
