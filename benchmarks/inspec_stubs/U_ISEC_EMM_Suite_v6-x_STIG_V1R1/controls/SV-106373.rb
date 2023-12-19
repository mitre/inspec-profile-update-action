control 'SV-106373' do
  title 'ISEC7 EMM Suite must disable or delete local account created during application installation and configuration.'
  desc 'The ISEC7 local account password complexity controls do not meet DoD requirements; therefore, admins have the capability to configure the account out of compliance, which could allow attacker to gain unauthorized access to the server and access to command MDM servers.'
  desc 'check', 'Log in to the ISEC7 EMM Suite console.
Navigate to Administration >> Configuration >> Account Management >> Users.
Select Edit next to the local account Admin.
Verify Login disabled has been selected.

If Login disabled has not been selected, this is a finding.'
  desc 'fix', 'Log in to the ISEC7 EMM Suite console.
Navigate to Administration >> Configuration  >> Account Management >> Users.
Select Edit next to the local account Admin.
Check Login disabled for the account.
Click Save.'
  impact 0.7
  ref 'DPMS Target ISEC7 EMM Suite v6.x'
  tag check_id: 'C-96087r1_chk'
  tag severity: 'high'
  tag gid: 'V-97249'
  tag rid: 'SV-106373r1_rule'
  tag stig_id: 'ISEC-06-000660'
  tag gtitle: 'SRG-APP-000148'
  tag fix_id: 'F-102931r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
