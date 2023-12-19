control 'SV-4351' do
  title 'The /etc/security/audit_user file must be group-owned by root, sys, or bin.'
  desc 'The Solaris audit_user file allows for selective auditing or non-auditing of features for certain users.  If it is not protected, it could be compromised and used to mask audit events.  This could cause the loss of valuable forensics data in the case of a system compromise.'
  desc 'fix', 'Change the group owner of the audit_user file to root, bin, or sys.
Example:
# chgrp root /etc/security/audit_user'
  impact 0.5
  ref 'DPMS Target Solaris 9 Sparc'
  tag severity: 'medium'
  tag gid: 'V-4351'
  tag rid: 'SV-4351r2_rule'
  tag stig_id: 'GEN000000-SOL00080'
  tag gtitle: 'GEN000000-SOL00080'
  tag fix_id: 'F-4262r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
