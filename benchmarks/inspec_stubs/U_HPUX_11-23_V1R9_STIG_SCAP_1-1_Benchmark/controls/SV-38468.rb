control 'SV-38468' do
  title 'The /etc/shadow (or equivalent) file must be owned by root.'
  desc "The /etc/shadow file contains the list of local system accounts.  It is vital to system security and must be protected from unauthorized modification.  Failure to give ownership of sensitive files or utilities to root or bin provides the designated owner and unauthorized users with the potential to access sensitive information or change the system configuration which could weaken the system's security posture."
  desc 'fix', 'For Trusted Mode:
# chown root /tcb
# chown root /tcb/files /tcb/files/auth
# chown root  /tcb/files/auth/[a-z]/* 

For SMSE:
# chown root /etc/shadow'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag severity: 'medium'
  tag gid: 'V-797'
  tag rid: 'SV-38468r2_rule'
  tag stig_id: 'GEN001400'
  tag gtitle: 'GEN001400'
  tag fix_id: 'F-31585r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
