control 'SV-37243' do
  title 'The /etc/security/access.conf file must have mode 0640 or less permissive.'
  desc 'If the access permissions are more permissive than 0640, system security could be compromised.'
  desc 'fix', 'Use the chmod command to set the permissions to 0640.
(for example:
# chmod 0640 /etc/security/access.conf

).'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-1055'
  tag rid: 'SV-37243r2_rule'
  tag stig_id: 'GEN000000-LNX00440'
  tag gtitle: 'GEN000000-LNX00440'
  tag fix_id: 'F-31190r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225', 'CCI-000366']
  tag nist: ['AC-6', 'CM-6 b']
end
