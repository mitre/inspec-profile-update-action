control 'SV-254884' do
  title "The Tanium application must be configured to use Tanium User Groups in a manner consistent with the model outlined within the environment's system documentation."
  desc 'It is important for information system owners to document authorized user groups for the Tanium application to avoid unauthorized access to systems. Misaligned implementation of user groups grants excessive access and results in potential compromise of "need-to-know" when it comes to information access.'
  desc 'check', 'Consult with the Tanium System Administrator to review the documented list of Tanium User Groups. 
 
1. Using a web browser on a system that has connectivity to the Tanium Application, access the Tanium Application web user interface (UI) and log on with multi-factor authentication.
 
2. Click "Administration" on the top navigation banner.
 
3. Under Permissions, select "User Groups".
 
4. Click each User Group and compare both the User Group name and the assigned Role(s) to the system documentation.
 
If any users have access to Tanium and their User Group is not on the list of documented User Groups with the appropriate Role(s), this is a finding.'
  desc 'fix', 'Consult the documentation identifying the Tanium User Groups and their respective Role(s).
 
1. Using a web browser on a system that has connectivity to the Tanium Application, access the Tanium Application web user interface (UI) and log on with multi-factor authentication. 
 
2. Click "Administration" on the top navigation banner.
 
3. Under Permissions, select "User Groups".
 
4. Click each User Group and add any missing Role(s).
 
5. For any missing User Groups, make the appropriate adjustments in LDAP.'
  impact 0.5
  ref 'DPMS Target Tanium 7.x Application on TanOS'
  tag check_id: 'C-58497r867550_chk'
  tag severity: 'medium'
  tag gid: 'V-254884'
  tag rid: 'SV-254884r867552_rule'
  tag stig_id: 'TANS-AP-000110'
  tag gtitle: 'SRG-APP-000033'
  tag fix_id: 'F-58441r867551_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
