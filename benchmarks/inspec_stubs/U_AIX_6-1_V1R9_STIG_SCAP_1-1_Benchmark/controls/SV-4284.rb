control 'SV-4284' do
  title 'The securetcpip command must be used.'
  desc 'The AIX securetcpip command disables insecure network utilities, such as rcp, rlogin, rlogind, rsh, rshd, tftp, tftpd, and trpt/d. These services increase the attack surface of the system.'
  desc 'fix', 'Ensure secure tcp/ip has been invoked before allowing operations on the system.'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag severity: 'medium'
  tag gid: 'V-4284'
  tag rid: 'SV-4284r2_rule'
  tag stig_id: 'GEN000000-AIX00040'
  tag gtitle: 'GEN000000-AIX00040'
  tag fix_id: 'F-33317r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000032']
  tag nist: ['AC-4 (8) (a)']
end
