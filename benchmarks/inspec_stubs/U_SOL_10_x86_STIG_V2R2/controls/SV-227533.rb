control 'SV-227533' do
  title 'The /etc/security/audit_user file must not define a different auditing level for specific users.'
  desc 'The audit_user file may be used to selectively audit more, or fewer, auditing features for specific individuals.  If used this way it could subject the activity to a lawsuit and could cause the loss of valuable auditing data in the case of a system compromise.  If an item is audited for one individual (other than for root and administrative users - who have more auditing features) it must be audited for all.'
  desc 'check', 'Perform:

	#	more /etc/security/audit_user

If /etc/security/audit_user has entries other than root, ensure the users defined are audited with the same flags as all users as defined in /etc/security/audit_control file.'
  desc 'fix', 'Edit the audit_user file and remove specific user configurations differing from the global audit settings.'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29695r488126_chk'
  tag severity: 'medium'
  tag gid: 'V-227533'
  tag rid: 'SV-227533r603266_rule'
  tag stig_id: 'GEN000000-SOL00040'
  tag gtitle: 'SRG-OS-000470'
  tag fix_id: 'F-29683r488127_fix'
  tag 'documentable'
  tag legacy: ['SV-4353', 'V-4353']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
