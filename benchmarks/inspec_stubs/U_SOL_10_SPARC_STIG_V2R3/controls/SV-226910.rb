control 'SV-226910' do
  title 'The inetd.conf file must not have extended ACLs.'
  desc 'The Internet service daemon configuration files must be protected as malicious modification could cause Denial of Service or increase the attack surface of the system.'
  desc 'check', 'Check the permissions of the inetd configuration file.
# ls -lL /etc/inet/inetd.conf
If the permissions include a "+", the file has an extended ACL and this is a finding.'
  desc 'fix', 'Remove the extended ACL from the file.
# chmod A- /etc/inet/inetd.conf'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-29072r485017_chk'
  tag severity: 'medium'
  tag gid: 'V-226910'
  tag rid: 'SV-226910r603265_rule'
  tag stig_id: 'GEN003745'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29060r485018_fix'
  tag 'documentable'
  tag legacy: ['SV-26653', 'V-22424']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
