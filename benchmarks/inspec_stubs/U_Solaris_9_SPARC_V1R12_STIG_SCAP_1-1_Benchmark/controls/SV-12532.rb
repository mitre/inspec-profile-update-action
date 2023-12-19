control 'SV-12532' do
  title 'The nosuid option must be configured in the /etc/rmmount.conf file.'
  desc 'The rmmount.conf file controls the mounting of removable media on a Solaris system. Removable media is not to be trusted with privileged access, and therefore the filesystems must be mounted with the nosuid option, which prevents any executables with the setuid bit set on this filesystem from running with owner privileges.'
  desc 'fix', 'Edit /etc/rmmount.conf and add the nosuid mount option to the configuration.'
  impact 0.5
  ref 'DPMS Target Solaris 9 Sparc'
  tag severity: 'medium'
  tag gid: 'V-12031'
  tag rid: 'SV-12532r2_rule'
  tag stig_id: 'GEN000000-SOL00020'
  tag gtitle: 'GEN000000-SOL00020'
  tag fix_id: 'F-11288r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECPA-1'
  tag cci: ['CCI-000225', 'CCI-000366']
  tag nist: ['AC-6', 'CM-6 b']
end
