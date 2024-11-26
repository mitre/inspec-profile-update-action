control 'SV-226979' do
  title 'The /etc/syslog.conf file must not have an extended ACL.'
  desc 'Unauthorized users must not be allowed to access or modify the /etc/syslog.conf file.'
  desc 'check', 'Check the permissions of the syslog configuration file.
# ls -lL /etc/syslog.conf
If the permissions include a "+", the file has an extended ACL and this is a finding.'
  desc 'fix', 'Remove the extended ACL from the file.
# chmod A- /etc/syslog.conf'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-29141r485267_chk'
  tag severity: 'medium'
  tag gid: 'V-226979'
  tag rid: 'SV-226979r603265_rule'
  tag stig_id: 'GEN005395'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29129r485268_fix'
  tag 'documentable'
  tag legacy: ['SV-26743', 'V-22454']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
