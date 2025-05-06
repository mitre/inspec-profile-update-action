control 'SV-245528' do
  title 'The Samsung SDS EMM local accounts must be configured with password maximum lifetime of 60 Days.'
  desc 'Any password, no matter how complex, can eventually be cracked. Therefore, passwords need to be changed at specific intervals.  
 
One method of minimizing this risk is to use complex passwords and periodically change them. If the application does not limit the lifetime of passwords and force users to change their passwords, there is the risk that the system and/or application passwords could be compromised.  
 
This requirement does not include emergency administration accounts which are meant for access to the application in case of failure. These accounts are not required to have maximum password lifetime restrictions.

SFR ID: FMT_SMF.1(2)b. / IA-5 (1) (d)'
  desc 'check', 'Verify Samsung SDS EMM local accounts have been configured to prohibit password reuse for a minimum of five generations.

1. Log in to the SDS EMM console.
2. Go to Setting >> Server >> Configuration >> Manage Password History (Times).
3. Verify the Manage Password History (Times) is set to 5.

If the Manage Password History (Times) is not set to 5, this is a finding.'
  desc 'fix', 'Configure Samsung SDS EMM local accounts with password maximum lifetime of 60 Days. On the MDM console, do the following: 

1.  Log in to the SDS EMM console.
2.  Go to Setting >> Server >> Configuration >> Manage Validity Period (Days).
3.  Set the Manage Validity Period (Days) to 60.
4.  Save setting.'
  impact 0.5
  ref 'DPMS Target Samsung SDS EMM'
  tag check_id: 'C-48803r836815_chk'
  tag severity: 'medium'
  tag gid: 'V-245528'
  tag rid: 'SV-245528r836815_rule'
  tag stig_id: 'SSDS-00-200210'
  tag gtitle: 'PP-MDM-991000'
  tag fix_id: 'F-48759r835015_fix'
  tag 'documentable'
  tag cci: ['CCI-000174']
  tag nist: ['AU-12 (1)']
end
