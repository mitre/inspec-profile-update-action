control 'SV-26441' do
  title 'The /etc/shadow file must not have an extended ACL.'
  desc 'The /etc/shadow file contains the list of local system accounts.  It is vital to system security and must be protected from unauthorized modification.  The file also contains password hashes which must not be accessible to users other than root.'
  desc 'check', 'For Trusted Mode:
Check the TCB auth files and directories.
# ls -lLd /tcb /tcb/files /tcp/files/auth 
# ls -lL /tcb/files/auth/[a-z,A-Z]/*

If the permissions of any of the /tcb files and directories include a “+”, this is a finding.

For SMSE:
Check the /etc/shadow file.
# ls -lL /etc/shadow

If the /etc/shadow file permissions include a “+”, the file has an extended ACL, this is a finding.'
  desc 'fix', 'For Trusted Mode:
# chacl -z /tcb
# chacl -z /tcb/files /tcb/files/auth
# chacl -z  /tcb/files/auth/[a-z]/* 

For SMSE:
# chacl -z /etc/shadow'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-36357r4_chk'
  tag severity: 'medium'
  tag gid: 'V-22340'
  tag rid: 'SV-26441r2_rule'
  tag stig_id: 'GEN001430'
  tag gtitle: 'GEN001430'
  tag fix_id: 'F-31693r3_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
