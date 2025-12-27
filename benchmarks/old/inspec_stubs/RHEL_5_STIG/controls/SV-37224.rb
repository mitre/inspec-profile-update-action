control 'SV-37224' do
  title 'The /etc/access.conf file must be owned by root.'
  desc 'The /etc/access.conf file contains entries restricting access from the system console by authorized System Administrators.  If the file is owned by a user other than root, it could compromise the system.'
  desc 'fix', 'Follow the correct configuration parameters for access configuration file. Use the chown command to configure it properly. 
(for example:
# chown root /etc/security/access.conf  
 ).'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-1025'
  tag rid: 'SV-37224r1_rule'
  tag stig_id: 'GEN000000-LNX00400'
  tag gtitle: 'GEN000000-LNX00400'
  tag fix_id: 'F-31171r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225', 'CCI-000366']
  tag nist: ['AC-6', 'CM-6 b']
end
