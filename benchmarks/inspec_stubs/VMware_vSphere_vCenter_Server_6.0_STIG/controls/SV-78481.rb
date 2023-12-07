control 'SV-78481' do
  title 'The system must minimize access to the vCenter server.'
  desc 'After someone has logged in to the vCenter Server system, it becomes more difficult to prevent what they can do. In general, logging in to the vCenter Server system should be limited to very privileged administrators, and then only for the purpose of administering vCenter Server or the host OS. Anyone logged in to the vCenter Server can potentially cause harm, either intentionally or unintentionally, by altering settings and modifying processes. They also have potential access to vCenter credentials, such as the SSL certificate.'
  desc 'check', 'Login to the vCenter server and verify the local administrators group only contains users and/or groups that contain vCenter Administrators.

If the local administrators group contains users and/or groups that are not vCenter Administrators such as "Domain Admins", this is a finding.'
  desc 'fix', 'Remove all unnecessary users and/or groups from the local administrators group of the vCenter server.'
  impact 0.7
  ref 'DPMS Target vCenter Server 6.0'
  tag check_id: 'C-64743r1_chk'
  tag severity: 'high'
  tag gid: 'V-63991'
  tag rid: 'SV-78481r1_rule'
  tag stig_id: 'VCWN-06-000027'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-69921r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
