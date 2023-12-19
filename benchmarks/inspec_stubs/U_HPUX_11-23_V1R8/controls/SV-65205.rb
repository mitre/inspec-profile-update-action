control 'SV-65205' do
  title 'The system must impose the same restrictions on root passwords that are already applied to non-root users.'
  desc 'Best practices and standard operating procedures for computing systems include password management. If the root account is allowed to be configured with inadequate password controls, the entire system can be compromised.'
  desc 'check', 'If the system is configured for Trusted Mode, this check is not applicable.

For Standard Mode with Security Extensions (SMSE):
Check the /etc/default/security file for the following attribute(s) and attribute values:
PASSWORD_POLICY_STRICT=1
# grep "PASSWORD_POLICY_STRICT" /etc/default/security

If PASSWORD_POLICY_STRICT=0, then the root user is not subject to the same password restrictions as non-root users, and this is a finding.'
  desc 'fix', 'If the system is operating in Trusted Mode, no fix is required.

For SMSE:
Edit the /etc/default/security file and add/modify the following attribute(s) and attribute values:
PASSWORD_POLICY_STRICT=1

Save the file before exiting the editor.'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-53445r2_chk'
  tag severity: 'medium'
  tag gid: 'V-50999'
  tag rid: 'SV-65205r2_rule'
  tag stig_id: 'GEN000000-HPUX0225'
  tag gtitle: 'GEN000000-HPUX0225'
  tag fix_id: 'F-55807r1_fix'
  tag 'documentable'
  tag ia_controls: 'IAIA-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
