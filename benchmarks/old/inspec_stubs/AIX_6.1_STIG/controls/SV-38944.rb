control 'SV-38944' do
  title 'The /etc/security/passwd file must be owned by root.'
  desc "The /etc/security/passwd file contains the list of local system accounts.  It is vital to system security and must be protected from unauthorized modification.  Failure to give ownership of sensitive files or utilities to root or bin provides the designated owner and unauthorized users with the potential to access sensitive information or change the system configuration which could weaken the system's security posture."
  desc 'check', 'Check the ownership of the /etc/security/passwd file.
Procedure:
# ls -lL /etc/security/passwd
If the owner of this file is not root, this is a finding.'
  desc 'fix', 'Change the ownership of the /etc/security/passwd file.
# chown root /etc/security/passwd'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-28148r1_chk'
  tag severity: 'medium'
  tag gid: 'V-797'
  tag rid: 'SV-38944r1_rule'
  tag stig_id: 'GEN001400'
  tag gtitle: 'GEN001400'
  tag fix_id: 'F-32285r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
