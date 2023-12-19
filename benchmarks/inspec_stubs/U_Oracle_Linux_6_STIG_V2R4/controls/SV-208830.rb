control 'SV-208830' do
  title 'System and application account passwords must be changed at least annually.'
  desc 'Any password, no matter how complex, can eventually be cracked. Therefore, system and application account passwords need to be changed periodically. If an organization fails to change the system and application account passwords at least annually, there is the risk that the account passwords could be compromised.'
  desc 'check', 'Obtain a list of approved system and application accounts from the ISSO.

For each system and application account identified, run the following command:

# chage -l <application_account>

Last password change				: Nov 05, 2018
Password expires				: Nov 04, 2019
Password inactive				: Dec 10, 2019
Account expires					: never
Minimum number of days between password change		: 1
Maximum number of days between password change		: 365
Number of days of warning before password expires	: 7

If "Maximum number of days between password change" is greater than "365", this is a finding.

If the date of "Last password change" exceeds 365 days, this is a finding.

If the date of "Password expires" is greater than 365 days from the date of "Last password change", this is a finding.'
  desc 'fix', 'Set the "Maximum number of days between password change" to "365":

# chage -M 365 <application_account>

Change the password for the system/application account:

#passwd <application_account>'
  impact 0.5
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9083r357470_chk'
  tag severity: 'medium'
  tag gid: 'V-208830'
  tag rid: 'SV-208830r603263_rule'
  tag stig_id: 'OL6-00-000055'
  tag gtitle: 'SRG-OS-000076'
  tag fix_id: 'F-9083r357471_fix'
  tag 'documentable'
  tag legacy: ['V-92247', 'SV-102349']
  tag cci: ['CCI-000199']
  tag nist: ['IA-5 (1) (d)']
end
