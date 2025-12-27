control 'SV-52432' do
  title 'The system must impose the same restrictions on root logins that are already applied to non-root users.'
  desc 'Best practices standard operating procedures for computing systems includes account management. If the root account is allowed to be configured without a password, or not configured to lock if there have been no logins to the root account for an organization defined time interval, the entire system can be compromised.'
  desc 'check', 'If the system is configured for Trusted Mode, this check is not applicable.

For Standard Mode with Security Extensions (SMSE):
Check the /etc/default/security file for the following attribute(s) and attribute values:
LOGIN_POLICY_STRICT=1
# grep “LOGIN_POLICY_STRICT” /etc/default/security

If LOGIN_POLICY_STRICT=0, then the root user is not subject to the same login restrictions as non-root users.  If no organizational exceptions for root are documented and LOGIN_POLICY_STRICT=0, then this is a finding.'
  desc 'fix', 'If the system is operating in Trusted Mode, no fix is required.

For SMSE:
Edit the /etc/default/security file and add/modify the following attribute(s) and attribute values:
LOGIN_POLICY_STRICT=1

Save the file before exiting the editor.'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-47005r2_chk'
  tag severity: 'medium'
  tag gid: 'V-40445'
  tag rid: 'SV-52432r2_rule'
  tag stig_id: 'GEN000000-HPUX0220'
  tag gtitle: 'GEN000000-HPUX0220'
  tag fix_id: 'F-45394r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
