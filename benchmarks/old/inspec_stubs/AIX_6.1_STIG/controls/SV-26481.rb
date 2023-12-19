control 'SV-26481' do
  title "Local initialization files must be group-owned by the user's primary group or root."
  desc "Local initialization files are used to configure the user's shell environment upon login.  Malicious modification of these files could compromise accounts upon logon."
  desc 'check', "Check user home directories for local initialization files group-owned by a group other than the user's primary group or root.

1.  List user accounts and their primary GID.
# cut -d : -f 1,4 /etc/passwd 

2. Check local initialization files for each user.
# ls -alL ~USER/.login ~USER/.cshrc ~USER/.logout ~USER/.profile ~USER/.bash_profile ~USER/.bashrc ~USER/.bash_logout ~USER/.env ~USER/.dtprofile ~USER/.dispatch ~USER/.emacs ~USER/.exrc

3.  If any file is not group-owned by root or the user's primary GID, this is a finding."
  desc 'fix', "Change the group owner of the local initialization file to the user's primary group, or root.
# chgrp [USER's primary GID] ~USER/[local initialization file]"
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-27543r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22361'
  tag rid: 'SV-26481r1_rule'
  tag stig_id: 'GEN001870'
  tag gtitle: 'GEN001870'
  tag fix_id: 'F-23709r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
