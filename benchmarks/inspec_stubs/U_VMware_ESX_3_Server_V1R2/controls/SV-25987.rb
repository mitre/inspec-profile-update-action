control 'SV-25987' do
  title 'The /etc/shadow file must not have an extended ACL.'
  desc 'The /etc/shadow file contains the list of local system accounts.  It is vital to system security and must be protected from unauthorized modification.  The file also contains password hashes which must not be accessible to users other than root.'
  desc 'check', "Verify /etc/shadow has no extended ACL.
# ls -lL /etc/shadow

If the permissions include a '+', the file has an extended ACL, this is a finding.

If the /etc/shadow file does not exist and the system is in Trusted Mode, this is not a finding. Verify Trusted Mode:
# ls -lLR /tcb/files/auth/<a-z,A-Z>
 
The TCB file(s) should exist and should not have an extended ACL."
  desc 'fix', 'Remove the extended ACL from the /etc/shadow file.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-27512r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22340'
  tag rid: 'SV-25987r1_rule'
  tag stig_id: 'GEN001430'
  tag gtitle: 'GEN001430'
  tag fix_id: 'F-26193r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
