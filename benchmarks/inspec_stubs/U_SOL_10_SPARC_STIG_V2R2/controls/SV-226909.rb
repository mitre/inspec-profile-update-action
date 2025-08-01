control 'SV-226909' do
  title 'The inetd.conf file must have mode 0440 or less permissive.'
  desc 'The Internet service daemon configuration files must be protected as malicious modification could cause Denial of Service or increase the attack surface of the system.'
  desc 'check', 'Check the mode of inetd.conf file.
# ls -lL /etc/inet/inetd.conf
If the mode of the file is more permissive than 0440, this is a finding.'
  desc 'fix', 'Change the mode of the inetd.conf file.
# chmod 0440 /etc/inet/inetd.conf'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-29071r485014_chk'
  tag severity: 'medium'
  tag gid: 'V-226909'
  tag rid: 'SV-226909r603265_rule'
  tag stig_id: 'GEN003740'
  tag gtitle: 'SRG-OS-000312'
  tag fix_id: 'F-29059r485015_fix'
  tag 'documentable'
  tag legacy: ['V-822', 'SV-39885']
  tag cci: ['CCI-002165']
  tag nist: ['AC-3 (4)']
end
