control 'SV-38269' do
  title 'All skeleton files and directories (typically in /etc/skel) must be owned by bin.'
  desc "If the skeleton files are not protected, unauthorized personnel could change user startup parameters and possibly jeopardize user files.  Failure to give ownership of sensitive files or utilities to bin provides the designated owner and unauthorized users with the potential to access sensitive information or change the system configuration which could weaken the system's security posture."
  desc 'check', 'Check skeleton files ownership.
# ls -alL /etc/skel


If a skeleton file is not owned by bin, this is a finding.'
  desc 'fix', 'Change the ownership of skeleton files with incorrect mode.
# chown bin <skeleton file>'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-36379r1_chk'
  tag severity: 'medium'
  tag gid: 'V-11984'
  tag rid: 'SV-38269r1_rule'
  tag stig_id: 'GEN001820'
  tag gtitle: 'GEN001820'
  tag fix_id: 'F-31717r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
