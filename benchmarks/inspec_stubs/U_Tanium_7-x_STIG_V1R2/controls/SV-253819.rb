control 'SV-253819' do
  title "The Tanium application must be configured to use Tanium User Groups in a manner consistent with the model outlined in the environment's system documentation."
  desc 'It is important for information system owners to document authorized User Groups for the Tanium application to avoid unauthorized access to systems. Misaligned implementation of User Groups grants excessive access and results in potential compromise of "need-to-know" for information access.'
  desc 'check', '1. Consult with the Tanium system administrator to review the documented list of Tanium User Groups. 
 
2. Using a web browser on a system that has connectivity to the Tanium application, access the Tanium application web user interface (UI) and log on with multifactor authentication.
 
3. Click "Administration" on the top navigation banner.
 
4. Under "Permissions", select "User Groups".
 
5. Click each User Group and compare both the User Group name and the assigned Role(s) to the system documentation.
 
If any users have access to Tanium and their User Group is not on the list of documented User Groups with the appropriate Role(s), this is a finding.'
  desc 'fix', 'Consult the documentation identifying the Tanium User Groups and their respective Role(s).
 
1. Using a web browser on a system that has connectivity to the Tanium application, access the Tanium application web UI and log on with multifactor authentication. 
 
2. Click "Administration" on the top navigation banner.
 
3. Under "Permissions", select "User Groups".
 
4. Click each User Group and add any missing Role(s).
 
5. For any missing User Groups, make the appropriate adjustments in LDAP.'
  impact 0.5
  ref 'DPMS Target Tanium 7.x'
  tag check_id: 'C-57271r842483_chk'
  tag severity: 'medium'
  tag gid: 'V-253819'
  tag rid: 'SV-253819r842485_rule'
  tag stig_id: 'TANS-CN-000006'
  tag gtitle: 'SRG-APP-000033'
  tag fix_id: 'F-57222r842484_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
