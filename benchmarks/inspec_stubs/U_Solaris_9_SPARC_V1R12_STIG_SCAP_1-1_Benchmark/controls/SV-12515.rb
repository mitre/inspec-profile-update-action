control 'SV-12515' do
  title 'All .Xauthority files must have mode 0600 or less permissive.'
  desc '.Xauthority files ensure the user is authorized to access the specific X Windows host.  Excessive permissions may permit unauthorized modification of these files, which could lead to Denial of Service to authorized access or allow unauthorized access to be obtained.'
  desc 'fix', 'Change the mode of the .Xauthority files.

Procedure:
# chmod 0600 .Xauthority'
  impact 0.5
  ref 'DPMS Target Solaris 9 Sparc'
  tag severity: 'medium'
  tag gid: 'V-12014'
  tag rid: 'SV-12515r2_rule'
  tag stig_id: 'GEN005180'
  tag gtitle: 'GEN005180'
  tag fix_id: 'F-11274r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
