control 'SV-76891' do
  title 'ColdFusion must limit privileges, within the Administrator Console, to change the software resident within software libraries.'
  desc 'Controlling the overall security posture of the server encompasses controlling the patches and versions of the software running within the production environment.  Patches are installed to fix security and bug issues.  Vendors will often supply a feature to uninstall the patch in the event the patch does not install correctly,  if the patch causes issues with hosted applications, or if the patch contains issues not found during testing.  The uninstall feature is meant to be used by an SA to maintain a secure and stable system.  In the event an attacker gains access to the uninstall functionality, he can then attempt to revert the system to an unsecure version which may have known and documented attacks that can be successful to compromise ColdFusion.  

To protect against this type of attack and to further define roles for users, access to the patch management functionality is important.  Proper protection is performed through assigning the appropriate roles to the users of the Administrator Console and through the least privileged permissions assigned at the OS level.'
  desc 'check', 'Within the Administrator Console, navigate to the "User Manager" page under the "Security" menu.  Review each defined user and ask the SA if the user should have access to server patch management functions.  For each user that should not be able to access patch management functions, review the roles assigned to the user account.

If the user has the "Server Updates" role, this is a finding.'
  desc 'fix', 'Navigate to the "User Manager" page under the "Security" menu.  Remove the "Server Updates" role from each user that should not have access to patch management functions.'
  impact 0.5
  ref 'DPMS Target ColdFusion 11'
  tag check_id: 'C-63205r5_chk'
  tag severity: 'medium'
  tag gid: 'V-62401'
  tag rid: 'SV-76891r1_rule'
  tag stig_id: 'CF11-03-000092'
  tag gtitle: 'SRG-APP-000133-AS-000092'
  tag fix_id: 'F-68321r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
