control 'SV-12485' do
  title 'All skeleton files and directories (typically in /etc/skel) must be owned by bin.'
  desc "If the skeleton files are not protected, unauthorized personnel could change user startup parameters and possibly jeopardize user files.  Failure to give ownership of sensitive files or utilities to bin provides the designated owner and unauthorized users with the potential to access sensitive information or change the system configuration which could weaken the system's security posture."
  desc 'fix', 'Change the ownership of skeleton files with incorrect mode.
# chown bin <skeleton file>'
  impact 0.5
  ref 'DPMS Target Solaris 9 Sparc'
  tag severity: 'medium'
  tag gid: 'V-11984'
  tag rid: 'SV-12485r2_rule'
  tag stig_id: 'GEN001820'
  tag gtitle: 'GEN001820'
  tag fix_id: 'F-11245r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
