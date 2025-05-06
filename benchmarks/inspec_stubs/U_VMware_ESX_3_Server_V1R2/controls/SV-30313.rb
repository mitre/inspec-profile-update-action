control 'SV-30313' do
  title 'The system boot loader must protect passwords using an MD5 or stronger cryptographic hash.'
  desc 'If system boot loader passwords are compromised, users with console access to the system may be able to alter the system boot configuration or boot the system into single user or maintenance mode, which could result in Denial-of-Service or unauthorized privileged access to the system.'
  desc 'check', "Consult vendor documentation for procedures concerning the system's boot loader. If the boot loader passwords are not protected using an MD5 hash or stronger, this is a finding."
  desc 'fix', "Consult vendor documentation for procedures concerning the system's boot loader.  Configure the boot loader to hash boot loader passwords using MD5 or a stronger hash."
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-30914r1_chk'
  tag severity: 'medium'
  tag gid: 'V-24624'
  tag rid: 'SV-30313r1_rule'
  tag stig_id: 'GEN008710'
  tag gtitle: 'GEN008710'
  tag fix_id: 'F-27516r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'IAIA-1, IAIA-2'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
