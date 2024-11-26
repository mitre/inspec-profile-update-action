control 'SV-218517' do
  title 'The rexecd service must not be installed.'
  desc 'The rexecd process provides a typically unencrypted, host-authenticated remote access service.  SSH should be used in place of this service.'
  desc 'check', 'Check if the rsh-server package is installed.

Procedure:
# rpm -qa | grep rsh-server

If a package is found, this is a finding.'
  desc 'fix', 'Remove the rsh-server package.

Procedure:
# rpm -e rsh-server'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19992r562675_chk'
  tag severity: 'medium'
  tag gid: 'V-218517'
  tag rid: 'SV-218517r603259_rule'
  tag stig_id: 'GEN003845'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-19990r562676_fix'
  tag 'documentable'
  tag legacy: ['V-22434', 'SV-64039']
  tag cci: ['CCI-000305', 'CCI-000381']
  tag nist: ['CM-7 (2)', 'CM-7 a']
end
