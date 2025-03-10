control 'SV-243128' do
  title 'The vCenter Server must minimize access to the vCenter server.'
  desc 'After someone has logged in to the vCenter Server system, it becomes more difficult to prevent what they can do. In general, logging in to the vCenter Server system should be limited to very privileged administrators, and then only for the purpose of administering vCenter Server or the host OS. Anyone logged in to the vCenter Server can potentially cause harm, either intentionally or unintentionally, by altering settings and modifying processes. They also have potential access to vCenter credentials, such as the SSL certificate.'
  desc 'check', 'Note: For vCenter Server Appliance, this is not applicable.

Login to the vCenter server and verify the only local administrators group contains users and/or groups that contain vCenter Administrators.

If the local administrators group contains users and/or groups that are not vCenter Administrators such as "Domain Admins", this is a finding.'
  desc 'fix', 'Remove all unnecessary users and/or groups from the local administrators group of the vCenter server.'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 vCenter'
  tag check_id: 'C-46403r719625_chk'
  tag severity: 'medium'
  tag gid: 'V-243128'
  tag rid: 'SV-243128r879887_rule'
  tag stig_id: 'VCTR-67-000073'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-46360r719626_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
