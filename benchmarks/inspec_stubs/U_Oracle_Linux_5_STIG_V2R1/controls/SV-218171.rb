control 'SV-218171' do
  title 'The /etc/security/access.conf file must be owned by root.'
  desc 'The /etc/security/access.conf file contains entries restricting access from the system console by authorized System Administrators.  If the file is owned by a user other than root, it could compromise the system.'
  desc 'check', 'Check access configuration ownership:

# ls -lL /etc/security/access.conf

If this file exists and is not owned by root, this is a finding.'
  desc 'fix', 'Follow the correct configuration parameters for access configuration file. Use the chown command to configure it properly. 
(for example:
# chown root /etc/security/access.conf  
 ).'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19646r553850_chk'
  tag severity: 'medium'
  tag gid: 'V-218171'
  tag rid: 'SV-218171r603259_rule'
  tag stig_id: 'GEN000000-LNX00400'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-19644r553851_fix'
  tag 'documentable'
  tag legacy: ['V-1025', 'SV-62875']
  tag cci: ['CCI-000366', 'CCI-000225']
  tag nist: ['CM-6 b', 'AC-6']
end
