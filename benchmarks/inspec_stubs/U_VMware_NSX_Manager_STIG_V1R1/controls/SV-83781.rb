control 'SV-83781' do
  title 'The NSX vCenter must prohibit password reuse for a minimum of five generations.'
  desc 'Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. 
 
To meet password policy requirements, passwords need to be changed at specific policy-based intervals. 
 
If the network device allows the user to consecutively reuse their password when that password has exceeded its defined lifetime, the end result is a password that is not changed as per policy requirements.'
  desc 'check', 'From the vSphere Web Client, go to Administration >> Single Sign-On >> Configuration >> Policies >> Password Policy. 

View the value of the "Restrict reuse" setting. 

If the "Restrict reuse" policy is not set to "5" or more, this is a finding.'
  desc 'fix', 'From the vSphere Web Client, go to Administration >> Single Sign-On >> Configuration >> Policies >> Password Policy.

Click "Edit" and enter "5" into the "Restrict reuse" setting. Click "OK".'
  impact 0.5
  ref 'DPMS Target VMware NSX 6 NDM'
  tag check_id: 'C-69617r1_chk'
  tag severity: 'medium'
  tag gid: 'V-69177'
  tag rid: 'SV-83781r1_rule'
  tag stig_id: 'VNSX-ND-000056'
  tag gtitle: 'SRG-APP-000165-NDM-000253'
  tag fix_id: 'F-75363r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000200']
  tag nist: ['IA-5 (1) (e)']
end
