control 'SV-26998' do
  title 'The access.conf file must not have an extended ACL.'
  desc 'If the access permissions are more permissive than 0640, system security could be compromised.'
  desc 'fix', 'Remove the extended ACL from the file.
# setfacl --remove-all /etc/security/access.conf'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-22595'
  tag rid: 'SV-26998r1_rule'
  tag stig_id: 'GEN000000-LNX00450'
  tag gtitle: 'GEN000000-LNX00450'
  tag fix_id: 'F-24264r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225', 'CCI-000366']
  tag nist: ['AC-6', 'CM-6 b']
end
