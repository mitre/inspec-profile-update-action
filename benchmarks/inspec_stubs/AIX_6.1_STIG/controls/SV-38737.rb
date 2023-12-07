control 'SV-38737' do
  title 'All skeleton files and directories (typically in /etc/skel) must be owned by root or bin.'
  desc "If the skeleton files are not protected, unauthorized personnel could change user startup parameters and possibly jeopardize user files.  Failure to give ownership of sensitive files or utilities to root or bin provides the designated owner and unauthorized users with the potential to access sensitive information or change the system configuration which could weaken the system's security posture."
  desc 'check', 'Check skeleton files ownership.

Procedure:
# ls -l /etc/security/.profile /etc/security/mkuser.sys

If a skeleton file is not owned by root or bin, this is a finding.'
  desc 'fix', 'Change the ownership of skeleton files with incorrect mode.

# chown root /etc/security/.profile /etc/security/mkuser.sys'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37238r1_chk'
  tag severity: 'medium'
  tag gid: 'V-11984'
  tag rid: 'SV-38737r1_rule'
  tag stig_id: 'GEN001820'
  tag gtitle: 'GEN001820'
  tag fix_id: 'F-32452r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
