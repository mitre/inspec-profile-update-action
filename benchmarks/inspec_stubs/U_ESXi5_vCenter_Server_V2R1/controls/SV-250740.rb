control 'SV-250740' do
  title 'The use of Linux-based clients must be restricted.'
  desc 'Although SSL-based encryption is used to protect communication between client components and vCenter Server or ESXi, the Linux versions of these components do not perform certificate validation. Even if the self-signed certificates are replaced on vCenter and ESXi with legitimate certificates signed by the local root certificate authority or a third party, communications with Linux clients are still vulnerable to MiTM attacks.'
  desc 'check', 'Verify all client operating systems connecting to the vCenter Server are not Linux.

If any client operating system connecting to the vCenter Server is Linux-based, this is a finding.'
  desc 'fix', 'Replace all Linux-based clients connecting to the vCenter Server with non-Linux-based clients.'
  impact 0.3
  ref 'DPMS Target VMware vCenter Server Version 5'
  tag check_id: 'C-54175r799908_chk'
  tag severity: 'low'
  tag gid: 'V-250740'
  tag rid: 'SV-250740r799910_rule'
  tag stig_id: 'VCENTER-000021'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-54129r799909_fix'
  tag 'documentable'
  tag legacy: ['SV-51417', 'V-39559']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
