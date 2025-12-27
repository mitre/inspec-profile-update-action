control 'SV-45136' do
  title 'All skeleton files and directories (typically in /etc/skel) must be owned by root or bin.'
  desc "If the skeleton files are not protected, unauthorized personnel could change user startup parameters and possibly jeopardize user files.  Failure to give ownership of sensitive files or utilities to root or bin provides the designated owner and unauthorized users with the potential to access sensitive information or change the system configuration which could weaken the system's security posture."
  desc 'check', 'Check skeleton files ownership.
# ls -alL /etc/skel
If a skeleton file is not owned by root or bin, this is a finding.'
  desc 'fix', %q(Change the ownership of skeleton files with incorrect mode:
# chown root <skeleton file>
or
# ls -L /etc/skel| awk '{ print "/etc/skel/"$1 }' |xargs stat -L -c %U:%n|egrep -v "^(root|bin):"|cut -d: -f2|xargs chown root 
will change all files not owned by root or bin to root.)
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42480r2_chk'
  tag severity: 'medium'
  tag gid: 'V-11984'
  tag rid: 'SV-45136r1_rule'
  tag stig_id: 'GEN001820'
  tag gtitle: 'GEN001820'
  tag fix_id: 'F-38532r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
