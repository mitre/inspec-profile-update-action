control 'SV-38735' do
  title 'All skeleton files (typically those in /etc/skel) must have mode 0644 or less permissive.'
  desc 'If the skeleton files are not protected, unauthorized personnel could change user startup parameters and possibly jeopardize user files.'
  desc 'check', "Check skeleton files permissions.

Procedure:
# ls -l /etc/security/.profile

If a skeleton file has a mode more permissive than 0644, this is a finding.
Check the mkuser.sys file.  The /etc/security/mkuser.sys is a script containing items used in creation of users' ~/.profile files.  This script needs to be both protected from unauthorized modification, but also needs to be executable,  therefore the permissions need to be at the mode of 755.
#ls -l /etc/security/mkuser.sys
If the mkuser.sys file has a mode more permissive than 0755, this is a finding."
  desc 'fix', 'Change the mode of skeleton files with incorrect mode.
# chmod 0644 /etc/security/.profile  
#chmod 0755 /etc/security/mkuser.sys'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37165r1_chk'
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
