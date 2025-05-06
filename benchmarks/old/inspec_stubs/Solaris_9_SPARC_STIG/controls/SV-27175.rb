control 'SV-27175' do
  title 'The NIS/NIS+/yp command files must have mode 0755 or less permissive.'
  desc "NIS/NIS+/yp files are part of the system's identification and authentication processes and are, therefore, critical to system security.  Unauthorized modification of these files could compromise these processes and the system."
  desc 'fix', 'Change the mode of NIS/NIS+/yp command files to 0755 or less permissive.

Procedure:
# chmod -R 0755 /usr/lib/netsvc/yp /var/yp'
  impact 0.5
  ref 'DPMS Target Solaris 9 Sparc'
  tag severity: 'medium'
  tag gid: 'V-791'
  tag rid: 'SV-27175r1_rule'
  tag stig_id: 'GEN001360'
  tag gtitle: 'GEN001360'
  tag fix_id: 'F-34672r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
