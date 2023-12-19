control 'SV-245527' do
  title 'The Samsung SDS EMM local accounts password must be configured with length of 15 characters.'
  desc 'The shorter the password, the lower the number of possible combinations that need to be tested before the password is compromised. 
 
Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. Password length is one factor of several that helps to determine strength and how long it takes to crack a password. The shorter the password, the lower the number of possible combinations that need to be tested before the password is compromised.  
 
Use of more characters in a password helps to exponentially increase the time and/or resources required to compromise the password.

SFR ID: FMT_SMF.1(2)b. / IA-5 (1) (a)'
  desc 'check', 'Verify  Samsung SDS EMM local accounts have been configured with a password with length of 15 characters or more.

1.  Log into the SDS EMM console.
2.  Go to Setting >> Server >> Configuration >> Minimum Password Length.
3.  Verify the Minimum Password Length is set to 15 or more.

If the Minimum Password Length is not set to 15 or more, this is a finding.'
  desc 'fix', 'Configure Samsung SDS EMM local accounts password with length of 15 characters or more. On the MDM console, do the following: 

1.  Log into the SDS EMM console.
2.  Go to Setting >> Server >> Configuration >> Minimum Password Length.
3.  Set the Minimum Password Length to 15.
4.  Save setting.'
  impact 0.5
  ref 'DPMS Target Samsung SDS EMM'
  tag check_id: 'C-48801r744404_chk'
  tag severity: 'medium'
  tag gid: 'V-245527'
  tag rid: 'SV-245527r744391_rule'
  tag stig_id: 'SSDS-00-200150'
  tag gtitle: 'PP-MDM-991000'
  tag fix_id: 'F-48758r744405_fix'
  tag 'documentable'
  tag cci: ['CCI-000205']
  tag nist: ['IA-5 (1) (a)']
end
