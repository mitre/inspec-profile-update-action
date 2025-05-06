control 'SV-108709' do
  title 'MySQL database backups must be scheduled in Jamf Pro EMM.'
  desc 'Database backups are a recognized best practice to protect against key data loss and possible adverse impacts to the mission of the organization.

SFR ID: FMT_SMF.1(2)b. / CM-6 b

'
  desc 'check', 'Verify MySQL of database backups have been scheduled in Jamf Pro EMM.

1. Open "Jamf Server Tools".
2. Click "Scheduled Backups" in the sidebar.
3. Verify backups are scheduled.

 If MySQL of database backups have not been scheduled in Jamf Pro EMM, this is a finding.'
  desc 'fix', 'Schedule MySQL of database backups in Jamf Pro EMM. 

The procedure is found in the following Jamf Knowledge Base article:

https://www.jamf.com/jamf-nation/articles/579/title'
  impact 0.5
  ref 'DPMS Target JAMF v10.x EMM'
  tag check_id: 'C-98455r1_chk'
  tag severity: 'medium'
  tag gid: 'V-99605'
  tag rid: 'SV-108709r1_rule'
  tag stig_id: 'JAMF-10-100110'
  tag gtitle: 'PP-MDM-991000'
  tag fix_id: 'F-105289r1_fix'
  tag satisfies: ['SRG-APP-000516']
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
