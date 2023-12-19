control 'SV-38735' do
  title 'All skeleton files (typically those in /etc/skel) must have mode 0644 or less permissive.'
  desc 'If the skeleton files are not protected, unauthorized personnel could change user startup parameters and possibly jeopardize user files.'
  desc 'fix', 'Change the mode of skeleton files with incorrect mode.
# chmod 0644 /etc/security/.profile  
#chmod 0755 /etc/security/mkuser.sys'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag severity: 'medium'
  tag gid: 'V-788'
  tag rid: 'SV-38735r1_rule'
  tag stig_id: 'GEN001800'
  tag gtitle: 'GEN001800'
  tag fix_id: 'F-32450r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
