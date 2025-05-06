control 'SV-1025' do
  title 'The /etc/access.conf file must be owned by root.'
  desc 'The /etc/access.conf file contains entries that restrict access from the system console by authorized System Administrators.  If the file were owned by a user other than root, it could compromise the system.'
  desc 'check', 'Check access configuration ownership:

# ls –lL /etc/login.access /etc/security/access.conf /etc/access.conf

If any of these files exist and are not owned by root, this is a finding.'
  desc 'fix', 'Follow the correct configuration parameters for access configuration file.  Use the chown command to configure it properly.  
For example:
# chown root /etc/login.access /etc/security/access.conf /etc/access.conf'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-28798r1_chk'
  tag severity: 'medium'
  tag gid: 'V-1025'
  tag rid: 'SV-1025r2_rule'
  tag stig_id: 'GEN000000-LNX00400'
  tag gtitle: 'GEN000000-LNX00400'
  tag fix_id: 'F-1179r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225', 'CCI-000366']
  tag nist: ['AC-6', 'CM-6 b']
end
