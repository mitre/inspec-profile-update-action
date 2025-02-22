control 'SV-245529' do
  title 'The Samsung SDS EMM local accounts must prohibit password reuse for a minimum of five generations.'
  desc 'Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.  
 
To meet password policy requirements, passwords need to be changed at specific policy-based intervals.  
 
If the information system or application allows the user to consecutively reuse their password when that password has exceeded its defined lifetime, the end result is a password that is not changed as per policy requirements.

SFR ID: FMT_SMF.1(2)b. / IA-5 (1) (e)'
  desc 'check', 'Verify Samsung SDS EMM local accounts have been configured to prohibit password reuse for a minimum of five generations.

1. Log in to the SDS EMM console.
2. Go to Setting >> Server >> Configuration >> Manage Password History (Times).
3. Verify the Manage Password History (Times) is set to 5.

If the Manage Password History (Times) is not set to 5, this is a finding.'
  desc 'fix', 'Configure Samsung SDS EMM local accounts to prohibit password reuse for a minimum of five generations. On the MDM console, do the following: 

1.  Log in to the SDS EMM console.
2.  Go to Setting >> Server >> Configuration >> Manage Password History (Times).
3.  Set the Manage Password History (Times) to 5.
4.  Save setting.'
  impact 0.5
  ref 'DPMS Target Samsung SDS EMM'
  tag check_id: 'C-48803r836815_chk'
  tag severity: 'medium'
  tag gid: 'V-245529'
  tag rid: 'SV-245529r836816_rule'
  tag stig_id: 'SSDS-00-200220'
  tag gtitle: 'PP-MDM-991000'
  tag fix_id: 'F-48760r744408_fix'
  tag 'documentable'
  tag cci: ['CCI-000200']
  tag nist: ['IA-5 (1) (e)']
end
