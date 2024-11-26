control 'SV-41532' do
  title "The system's access control program must be configured to grant or deny system access to specific hosts."
  desc "If the system's access control program is not configured with appropriate rules for allowing and denying access to system network resources, services may be accessible to unauthorized hosts."
  desc 'fix', 'Edit the /etc/hosts.allow and /etc/hosts.deny files to configure access restrictions.'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag severity: 'medium'
  tag gid: 'V-12030'
  tag rid: 'SV-41532r1_rule'
  tag stig_id: 'GEN006620'
  tag gtitle: 'GEN006620'
  tag fix_id: 'F-11287r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
