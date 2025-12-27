control 'SV-242615' do
  title 'The Cisco ISE must prevent non-privileged users from executing privileged functions to include disabling, circumventing, or altering implemented security safeguards/countermeasures.'
  desc 'Preventing non-privileged users from executing privileged functions mitigates the risk that unauthorized individuals or processes may gain unnecessary access to information or privileges. 

Privileged functions include, for example, establishing accounts, performing system integrity checks, or administering cryptographic key management activities. Non-privileged users are individuals that do not possess appropriate authorizations.'
  desc 'check', 'Verify that only administrator accounts are located in administrative groups. 

From the web Admin portal:
1. Navigate to Administration >> System >> Admin Access >> Authorization >> Permissions >> Policy.
2. Verify non-administrative users are located in read only or limited access admin groups. If non-adminstrative accounts are in administrative admin groups, this is a finding.'
  desc 'fix', 'Configure Role Based Access Control to ensure only administrator accounts have admin or super admin rights. 

From web Admin portal: 
1. Navigate to Administration >> System >> Admin Access >> Authorization >> Permissions > Policy.
2. Take note of admin account groups.
3. Navigate to Administration >> System >> Admin Access >> Administrators >> Admin Users.
4. Ensure only admin accounts are placed within admin groups.

Note: If Active Directory is in use for external authentication, verify from AD that only administrative users are in the security group used for ISE admins.'
  impact 0.7
  ref 'DPMS Target Cisco ISE NDM'
  tag check_id: 'C-45890r803574_chk'
  tag severity: 'high'
  tag gid: 'V-242615'
  tag rid: 'SV-242615r879717_rule'
  tag stig_id: 'CSCO-NM-000090'
  tag gtitle: 'SRG-APP-000340-NDM-000288'
  tag fix_id: 'F-45847r803575_fix'
  tag 'documentable'
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
