control 'SV-227532' do
  title 'The nosuid option must be configured in the /etc/rmmount.conf file.'
  desc 'The rmmount.conf file controls the mounting of removable media on a Solaris system. Removable media is not to be trusted with privileged access, and therefore the filesystems must be mounted with the nosuid option, which prevents any executables with the setuid bit set on this filesystem from running with owner privileges.'
  desc 'check', '# grep mount /etc/rmmount.conf

Confirm the nosuid option is configured.

mount * hsfs udfs ufs -o nosuid

If the nosuid option is not configured in the /etc/rmmount.conf file, this is a finding.'
  desc 'fix', 'Edit /etc/rmmount.conf and add the nosuid mount option to the configuration.'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29694r488123_chk'
  tag severity: 'medium'
  tag gid: 'V-227532'
  tag rid: 'SV-227532r603266_rule'
  tag stig_id: 'GEN000000-SOL00020'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29682r488124_fix'
  tag 'documentable'
  tag legacy: ['V-12031', 'SV-12532']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
