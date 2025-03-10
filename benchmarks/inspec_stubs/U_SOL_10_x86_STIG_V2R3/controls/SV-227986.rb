control 'SV-227986' do
  title 'The system package management tool must cryptographically verify the authenticity of software packages during installation.'
  desc 'To prevent the installation of software from unauthorized sources, the system package management tool must use cryptographic algorithms to verify the packages are authentic.'
  desc 'check', 'Verify package signature validation is not disabled.
# grep "authentication=quit" /var/sadm/install/admin/default
If no configuration is returned, this is a finding.'
  desc 'fix', 'Edit /var/sadm/install/admin/default and set the authentication setting to quit.'
  impact 0.3
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-30148r490417_chk'
  tag severity: 'low'
  tag gid: 'V-227986'
  tag rid: 'SV-227986r854523_rule'
  tag stig_id: 'GEN008800'
  tag gtitle: 'SRG-OS-000366'
  tag fix_id: 'F-30136r490418_fix'
  tag 'documentable'
  tag legacy: ['V-22588', 'SV-26991']
  tag cci: ['CCI-001749']
  tag nist: ['CM-5 (3)']
end
