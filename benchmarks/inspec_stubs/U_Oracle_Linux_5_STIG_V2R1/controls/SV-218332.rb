control 'SV-218332' do
  title 'All skeleton files and directories (typically in /etc/skel) must be owned by root or bin.'
  desc "If the skeleton files are not protected, unauthorized personnel could change user startup parameters and possibly jeopardize user files.  Failure to give ownership of sensitive files or utilities to root or bin provides the designated owner and unauthorized users with the potential to access sensitive information or change the system configuration which could weaken the system's security posture."
  desc 'check', 'Check skeleton files ownership.
# ls -alL /etc/skel
If a skeleton file is not owned by root or bin, this is a finding.'
  desc 'fix', 'Change the ownership of skeleton files with incorrect mode:
# chown root <skeleton file>
or
# ls -L /etc/skel|xargs stat -L -c %U:%n|egrep -v "^(root|bin):"|cut -d: -f2|chown root 
will change all files not owned by root or bin to root.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19807r568861_chk'
  tag severity: 'medium'
  tag gid: 'V-218332'
  tag rid: 'SV-218332r603259_rule'
  tag stig_id: 'GEN001820'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-19805r568862_fix'
  tag 'documentable'
  tag legacy: ['V-11984', 'SV-63307']
  tag cci: ['CCI-000225', 'CCI-001499']
  tag nist: ['AC-6', 'CM-5 (6)']
end
