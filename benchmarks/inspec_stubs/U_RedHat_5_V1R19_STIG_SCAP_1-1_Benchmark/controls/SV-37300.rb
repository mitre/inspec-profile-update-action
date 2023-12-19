control 'SV-37300' do
  title 'All skeleton files and directories (typically in /etc/skel) must be owned by root or bin.'
  desc "If the skeleton files are not protected, unauthorized personnel could change user startup parameters and possibly jeopardize user files.  Failure to give ownership of sensitive files or utilities to root or bin provides the designated owner and unauthorized users with the potential to access sensitive information or change the system configuration which could weaken the system's security posture."
  desc 'fix', 'Change the ownership of skeleton files with incorrect mode:
# chown root <skeleton file>
or
# ls -L /etc/skel|xargs stat -L -c %U:%n|egrep -v "^(root|bin):"|cut -d: -f2|chown root 
will change all files not owned by root or bin to root.'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-11984'
  tag rid: 'SV-37300r1_rule'
  tag stig_id: 'GEN001820'
  tag gtitle: 'GEN001820'
  tag fix_id: 'F-31248r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
