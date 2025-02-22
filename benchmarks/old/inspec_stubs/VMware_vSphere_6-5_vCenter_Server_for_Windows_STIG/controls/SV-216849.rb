control 'SV-216849' do
  title 'The vCenter Server for Windows must minimize access to the vCenter server.'
  desc 'After someone has logged in to the vCenter Server system, it becomes more difficult to prevent what they can do. In general, logging in to the vCenter Server system should be limited to very privileged administrators, and then only for the purpose of administering vCenter Server or the host OS. Anyone logged in to the vCenter Server can potentially cause harm, either intentionally or unintentionally, by altering settings and modifying processes. They also have potential access to vCenter credentials, such as the SSL certificate.'
  desc 'check', 'Login to the vCenter server and verify the only local administrators group contains users and/or groups that contain vCenter Administrators.

If the local administrators group contains users and/or groups that are not vCenter Administrators such as "Domain Admins", this is a finding.'
  desc 'fix', 'Remove all unnecessary users and/or groups from the local administrators group of the vCenter server.'
  impact 0.7
  ref 'DPMS Target VMW vSphere 6.5 vCenter Server for Windows'
  tag check_id: 'C-18080r366261_chk'
  tag severity: 'high'
  tag gid: 'V-216849'
  tag rid: 'SV-216849r879887_rule'
  tag stig_id: 'VCWN-65-000027'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-18078r366262_fix'
  tag 'documentable'
  tag legacy: ['SV-104593', 'V-94763']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
