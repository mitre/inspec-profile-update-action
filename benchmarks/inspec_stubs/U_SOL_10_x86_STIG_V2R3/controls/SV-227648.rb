control 'SV-227648' do
  title 'The /etc/shadow (or equivalent) file must be owned by root.'
  desc "The /etc/shadow file contains the list of local system accounts.  It is vital to system security and must be protected from unauthorized modification.  Failure to give ownership of sensitive files or utilities to root provides the designated owner and unauthorized users with the potential to access sensitive information or change the system configuration which could weaken the system's security posture."
  desc 'check', 'Check the ownership of the /etc/shadow file.
# ls -lL /etc/shadow
If the /etc/shadow file is not owned by root, this is a finding.'
  desc 'fix', 'Change the ownership of the /etc/shadow file.
# chown root /etc/shadow'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29810r488504_chk'
  tag severity: 'medium'
  tag gid: 'V-227648'
  tag rid: 'SV-227648r854478_rule'
  tag stig_id: 'GEN001400'
  tag gtitle: 'SRG-OS-000312'
  tag fix_id: 'F-29798r488505_fix'
  tag 'documentable'
  tag legacy: ['V-797', 'SV-39826']
  tag cci: ['CCI-002165']
  tag nist: ['AC-3 (4)']
end
