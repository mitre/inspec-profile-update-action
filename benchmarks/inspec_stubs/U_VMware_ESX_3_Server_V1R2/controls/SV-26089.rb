control 'SV-26089' do
  title 'The xinetd.d directory must have mode 0755 or less permissive.'
  desc 'The Internet service daemon configuration files must be protected as malicious modification could cause Denial-of-Service or increase the attack surface of the system.'
  desc 'check', 'Check the xinetd.conf file for any included directories.

Procedure:
# grep includedir /etc/xinetd.conf

If xinetd.conf does not exist, or there are no includedir lines contained within it, this is not applicable.

Check the mode of the included directories.
Procedure:
# ls -lL <directory>

If any of the included directories have a mode more permissive than 0755, this is a finding.'
  desc 'fix', 'Change the mode of included xinetd configuration directories to 0755.

Procedure:
# chmod 0755 <directory>'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-30071r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22425'
  tag rid: 'SV-26089r1_rule'
  tag stig_id: 'GEN003750'
  tag gtitle: 'GEN003750'
  tag fix_id: 'F-26900r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
