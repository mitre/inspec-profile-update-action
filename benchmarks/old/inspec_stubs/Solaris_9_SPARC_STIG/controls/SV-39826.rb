control 'SV-39826' do
  title 'The /etc/shadow (or equivalent) file must be owned by root.'
  desc "The /etc/shadow file contains the list of local system accounts.  It is vital to system security and must be protected from unauthorized modification.  Failure to give ownership of sensitive files or utilities to root provides the designated owner and unauthorized users with the potential to access sensitive information or change the system configuration which could weaken the system's security posture."
  desc 'fix', 'Change the ownership of the /etc/shadow file.
# chown root /etc/shadow'
  impact 0.5
  ref 'DPMS Target Solaris 9 Sparc'
  tag severity: 'medium'
  tag gid: 'V-797'
  tag rid: 'SV-39826r1_rule'
  tag stig_id: 'GEN001400'
  tag gtitle: 'GEN001400'
  tag fix_id: 'F-34673r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
