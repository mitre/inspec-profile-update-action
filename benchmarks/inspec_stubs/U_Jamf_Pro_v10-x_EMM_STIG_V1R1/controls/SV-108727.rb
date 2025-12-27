control 'SV-108727' do
  title 'The Jamf Pro EMM local accounts must prohibit password reuse for a minimum of five generations.'
  desc 'Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. 

To meet password policy requirements, passwords need to be changed at specific policy-based intervals. 

If the information system or application allows the user to consecutively reuse their password when that password has exceeded its defined lifetime, the end result is a password that is not changed as per policy requirements.

SFR ID: FMT_SMF.1(2)b. / IA-5 (1) (e)

'
  desc 'check', 'To verify the local accounts "Password History" is set to a minimum of "5" generations, do the following:

1. Open the Jamf Pro EMM console.
2. Click "Settings".
3. Click "System Settings".
4. Click "Jamf Pro System User Accounts & Groups".
5. Click "Password Policy".
6. Verify "Password History" to "5" or more.

If "Password History" is not set to "5" or more, this is a finding.'
  desc 'fix', 'Note: This requirement is NA if Option #1 is selected in requirement JAMF-10-000685.

To configure the "Password History" of the local accounts password to a minimum of "5" generations, do the following:

1. Open the Jamf Pro EMM console.
2. Click "Settings".
3. Click "System Settings".
4. Click "Jamf Pro System User Accounts & Groups".
5. Click "Password Policy".
6. Set the "Password History" to "5" or more.'
  impact 0.5
  ref 'DPMS Target JAMF v10.x EMM'
  tag check_id: 'C-98473r1_chk'
  tag severity: 'medium'
  tag gid: 'V-99623'
  tag rid: 'SV-108727r1_rule'
  tag stig_id: 'JAMF-10-100780'
  tag gtitle: 'PP-MDM-991000'
  tag fix_id: 'F-105307r1_fix'
  tag satisfies: ['SRG-APP-000165']
  tag 'documentable'
  tag cci: ['CCI-000200']
  tag nist: ['IA-5 (1) (e)']
end
