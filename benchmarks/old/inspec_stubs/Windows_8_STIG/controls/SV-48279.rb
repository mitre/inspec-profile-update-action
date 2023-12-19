control 'SV-48279' do
  title 'Application account passwords must be changed at least annually or when a system administrator with knowledge of the password leaves the organization.'
  desc 'Setting application accounts to expire may cause applications to stop functioning.  The site will have a policy that application account passwords are changed at least annually or when a system administrator with knowledge of the password leaves the organization.'
  desc 'check', 'The site must have a policy to ensure passwords for manually managed application/service accounts are changed at least annually or whenever a system administrator that has knowledge of the password leaves the organization.  If such a policy does not exist or has not been implemented, this is a finding.

Run the DUMPSEC utility.
Select "Dump Users as Table" from the "Report" menu.
Select the following fields, and click "Add" for each entry.

UserName
SID
PwsdLastSetTime 
AcctDisabled

If any application accounts listed have a date older than one year in the "PwsdLastSetTime" column, this is a finding.'
  desc 'fix', 'Establish a site policy that defines the requirements for application/service account password changes.

Change application/service account passwords that are manually managed and entered by a system administrator at least annually or whenever an administrator with knowledge of the password leaves the organization.'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44957r1_chk'
  tag severity: 'medium'
  tag gid: 'V-36662'
  tag rid: 'SV-48279r2_rule'
  tag stig_id: 'WN08-00-000010-02'
  tag gtitle: 'WIN00-000010-02'
  tag fix_id: 'F-41414r1_fix'
  tag 'documentable'
  tag ia_controls: 'IAIA-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
