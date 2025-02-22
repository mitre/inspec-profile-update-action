control 'SV-46089' do
  title 'The /etc/security/access.conf file must have mode 0640 or less permissive.'
  desc 'If the access permissions are more permissive than 0640, system security could be compromised.'
  desc 'check', 'Check access configuration mode:

 

# ls -lL /etc/security/access.conf

 

If this file exists and has a mode more permissive than 0640, this is a finding.'
  desc 'fix', 'Use the chmod command to set the permissions to 0640.

(for example:

# chmod 0640 /etc/security/access.conf'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43346r1_chk'
  tag severity: 'medium'
  tag gid: 'V-1055'
  tag rid: 'SV-46089r1_rule'
  tag stig_id: 'GEN000000-LNX00440'
  tag gtitle: 'GEN000000-LNX00440'
  tag fix_id: 'F-39433r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225', 'CCI-000366']
  tag nist: ['AC-6', 'CM-6 b']
end
