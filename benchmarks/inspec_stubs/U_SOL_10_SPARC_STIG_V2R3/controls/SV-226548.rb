control 'SV-226548' do
  title 'All skeleton files and directories (typically in /etc/skel) must be owned by root.'
  desc "If the skeleton files are not protected, unauthorized personnel could change user startup parameters and possibly jeopardize user files.  Failure to give ownership of sensitive files or utilities to root provides the designated owner and unauthorized users with the potential to access sensitive information or change the system configuration which could weaken the system's security posture."
  desc 'check', 'Check skeleton files ownership.
# ls -alL /etc/skel
If a skeleton file is not owned by root, this is a finding.'
  desc 'fix', 'Change the ownership of skeleton files with incorrect mode.
# chown root <skeleton file>'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-28709r483050_chk'
  tag severity: 'medium'
  tag gid: 'V-226548'
  tag rid: 'SV-226548r603265_rule'
  tag stig_id: 'GEN001820'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-28697r483051_fix'
  tag 'documentable'
  tag legacy: ['SV-12485', 'V-11984']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
