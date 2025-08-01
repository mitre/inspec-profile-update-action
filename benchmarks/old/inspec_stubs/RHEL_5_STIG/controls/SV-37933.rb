control 'SV-37933' do
  title 'The system boot loader must require authentication.'
  desc "If the system's boot loader does not require authentication, users with console access to the system may be able to alter the system boot configuration or boot the system into single user or maintenance mode, which could result in Denial of Service or unauthorized privileged access to the system."
  desc 'fix', 'The GRUB console boot loader can be configured to use an MD5 encrypted password by adding password --md5 password-hash to the "/boot/grub/grub.conf" file. Use "/sbin/grub-md5-crypt" to generate MD5 passwords from the command line.'
  impact 0.7
  ref 'DPMS Target Red Hat 5'
  tag severity: 'high'
  tag gid: 'V-4249'
  tag rid: 'SV-37933r1_rule'
  tag stig_id: 'GEN008700'
  tag gtitle: 'GEN008700'
  tag fix_id: 'F-32425r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'IAIA-1, IAIA-2'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
