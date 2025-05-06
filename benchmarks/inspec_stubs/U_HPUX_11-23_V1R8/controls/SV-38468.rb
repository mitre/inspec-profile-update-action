control 'SV-38468' do
  title 'The /etc/shadow (or equivalent) file must be owned by root.'
  desc "The /etc/shadow file contains the list of local system accounts.  It is vital to system security and must be protected from unauthorized modification.  Failure to give ownership of sensitive files or utilities to root or bin provides the designated owner and unauthorized users with the potential to access sensitive information or change the system configuration which could weaken the system's security posture."
  desc 'check', 'For Trusted Mode:
Check the ownership of the /etc/shadow file.
# ls -lL /etc/shadow

If the /etc/shadow file exists and is not owned by root, this is a finding. NOTE: /etc/shadow should not exist if the system is in Trusted Mode.

Check the ownership of the TCB auth files and directories.
# ls -lLd /tcb /tcb/files /tcb/files/auth 
# ls -lL /tcb/files/auth/[a-z,A-Z]/*

If the owner of any of the /tcb files and directories is not root, this is a finding.

For SMSE:
Check the /etc/shadow file.
# ls -lL /etc/shadow

If the /etc/shadow file exists and is not owned by root, this is a finding.'
  desc 'fix', 'For Trusted Mode:
# chown root /tcb
# chown root /tcb/files /tcb/files/auth
# chown root  /tcb/files/auth/[a-z]/* 

For SMSE:
# chown root /etc/shadow'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-36330r4_chk'
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
