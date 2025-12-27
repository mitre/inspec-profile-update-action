control 'SV-3369' do
  title 'Restricted accounts are not disabled.'
  desc 'Several new accounts are created as part of the default installation.  As these accounts are well known they may represent prime attack targets.  To help prevent attacks using the well-known accounts the following accounts should be disabled: HelpAssistant and Support_388945a0.'
  desc 'check', 'Using the DUMPSEC utility:

Select “Dump Users as Table” from the “Report” menu.
Select the available fields in the following sequence, and click on the “Add” button for each entry:
UserName
SID
PswdRequired
PswdExpires
LastLogonTime
AcctDisabled
Groups

If the HelpAssistant or Support_388945a0 accounts have not been disabled, then this is a finding.'
  desc 'fix', 'Configure the system to disable restricted accounts such as HelpAssistant or Support_388945a0.'
  impact 0.5
  ref 'DPMS Target Windows XP'
  tag check_id: 'C-504r1_chk'
  tag severity: 'medium'
  tag gid: 'V-3369'
  tag rid: 'SV-3369r1_rule'
  tag gtitle: 'Restricted Accounts are not Disabled'
  tag fix_id: 'F-5804r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'IAAC-1'
end
