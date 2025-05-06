control 'SV-227535' do
  title 'The /etc/security/audit_user file must be group-owned by root, sys, or bin.'
  desc 'The Solaris audit_user file allows for selective auditing or non-auditing of features for certain users.  If it is not protected, it could be compromised and used to mask audit events.  This could cause the loss of valuable forensics data in the case of a system compromise.'
  desc 'check', 'Check /etc/security/audit_user group ownership.

# ls -lL /etc/security/audit_user

If /etc/security/audit_user is not group owned by root, sys, or bin, this is a finding.'
  desc 'fix', 'Change the group owner of the audit_user file to root, bin, or sys.
Example:
# chgrp root /etc/security/audit_user'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29697r488132_chk'
  tag severity: 'medium'
  tag gid: 'V-227535'
  tag rid: 'SV-227535r603266_rule'
  tag stig_id: 'GEN000000-SOL00080'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29685r488133_fix'
  tag 'documentable'
  tag legacy: ['SV-4351', 'V-4351']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
