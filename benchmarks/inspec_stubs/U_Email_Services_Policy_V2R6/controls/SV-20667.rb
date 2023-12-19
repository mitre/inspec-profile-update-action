control 'SV-20667' do
  title 'Email Administrator Groups must ensure least privilege.'
  desc 'When an oversight responsibility is assigned to the same person performing the actions being overseen, the function of oversight is compromised. When the responsibility to manage or control one application or activity is assigned to one party yet another party is also assigned the privilege to the same actions, then neither party can logically be held responsible for those action. By separating responsibility and permissions by role, accountability can be as granular as needed. 

Role Based Access Control (RBAC) strategies for email administration include server role administration, permissions within server roles, and task based assignments.  Further granularity is possible, and often makes sense to do, enabling each role to operate using the least possible permissions to perform the role.'
  desc 'check', 'Review EDSP documentation that describes division of duties by role in the email domain administration assignments. 

If Email Administrator tasks are assigned to a defined role in the organization, and the role is operating at least privilege for the tasks, this is not a finding.'
  desc 'fix', 'Assign administrators to roles with appropriate permissions for Email Administrators.  Configure each role so it is commensurate with least possible permission to perform the associated tasks.'
  impact 0.5
  ref 'DPMS Target E-mail Services Policy'
  tag check_id: 'C-22520r4_chk'
  tag severity: 'medium'
  tag gid: 'V-18877'
  tag rid: 'SV-20667r3_rule'
  tag stig_id: 'EMG0-075 EMail'
  tag gtitle: 'EMG0-075 Email Admin Privileges Granted by Role'
  tag fix_id: 'F-19470r3_fix'
  tag 'documentable'
  tag responsibility: 'Other'
  tag ia_controls: 'ECPA-1'
end
