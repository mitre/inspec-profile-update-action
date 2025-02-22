control 'SV-34926' do
  title "Local initialization files must be group-owned by the user's primary group or root."
  desc "Local initialization files are used to configure the user's shell environment upon login.  Malicious modification of these files could compromise accounts upon logon."
  desc 'check', %q(Check user home directories for local initialization files group-owned by a group other than the user's primary group or root.

1. List user accounts and their primary GID.
# cat /etc/passwd | cut -f 1,4 -d ":"

2. Check local initialization files for each user. Field #1 above is USER and Field #4 is the user's GID.
# ls -alL ~USER/.login ~USER/.cshrc ~USER/.logout ~USER/.profile ~USER/.bash_profile ~USER/.bashrc ~USER/.bash_logout ~USER/.env ~USER/.dtprofile ~USER/.dispatch ~USER/.emacs ~USER/.exrc

3. If any file is not group-owned by root or the user's primary GID, this is a finding.)
  desc 'fix', "Change the group-owner of the local initialization file to the user's primary group or root.
# chgrp [USER's primary GID] ~USER/[local initialization file]"
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-36389r2_chk'
  tag severity: 'medium'
  tag gid: 'V-22361'
  tag rid: 'SV-34926r1_rule'
  tag stig_id: 'GEN001870'
  tag gtitle: 'GEN001870'
  tag fix_id: 'F-31730r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
