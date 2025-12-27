control 'SV-29511' do
  title 'Local users exist on a workstation in a domain.'
  desc 'To minimize potential points of attack, local users, other than built-in accounts such as Administrator and Guest accounts, should not exist on a workstation in a domain.  Users should always log onto workstations in a domain with their domain accounts.  This does not apply to laptop PCs which are designed to function both on the domain and off the domain.'
  desc 'check', 'If local users other than the built-in accounts listed below exist on a workstation in a domain this is a finding. 

Built-in Administrator (renamed)
Built-in Guest (renamed)
HelpAssistant (XP only)
Support_388945a0 (XP only)

The Gold Disk will return a list of local accounts for review to determine applicability.

Note: This does not apply to laptops that are designed to function both as part of a domain and separate from it.  

Using the DUMPSEC utility:

Select “Dump Users as Table” from the “Report” menu.
Select the available fields in the following sequence, and click on the “Add” button for each entry:
UserName
SID
PswdRequired
PswdExpires
LastLogonTime
AcctDisabled
Groups
 
Documentable Explanation: If a site has need of special purpose local user accounts, then this should be documented with the IAO.'
  desc 'fix', 'Configure the system to restrict the existence of local user accounts.'
  impact 0.3
  ref 'DPMS Target Windows XP'
  tag check_id: 'C-416r1_chk'
  tag severity: 'low'
  tag gid: 'V-1148'
  tag rid: 'SV-29511r1_rule'
  tag gtitle: 'Local Users Exist on a Workstation'
  tag fix_id: 'F-5764r1_fix'
  tag false_positives: 'This does not apply to laptops that are designed to function both as part of a domain and separate from it.'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag ia_controls: 'IAAC-1'
end
