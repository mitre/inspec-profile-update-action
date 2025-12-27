control 'SV-44652' do
  title 'The /etc/access.conf file must be owned by root.'
  desc 'The /etc/access.conf file contains entries restricting access from the system console by authorized System Administrators.  If the file is owned by a user other than root, it could compromise the system.'
  desc 'check', 'Check access configuration ownership:

# ls -lL /etc/security/access.conf

If this file exists and is not owned by root, this is a finding.'
  desc 'fix', 'Follow the correct configuration parameters for access configuration file. Use the chown command to configure it properly. 
(for example:
# chown root /etc/security/access.conf).'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42156r1_chk'
  tag severity: 'medium'
  tag gid: 'V-1025'
  tag rid: 'SV-44652r1_rule'
  tag stig_id: 'GEN000000-LNX00400'
  tag gtitle: 'GEN000000-LNX00400'
  tag fix_id: 'F-38107r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225', 'CCI-000366']
  tag nist: ['AC-6', 'CM-6 b']
end
