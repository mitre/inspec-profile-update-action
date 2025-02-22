control 'SV-237901' do
  title 'The CA VM:Secure JOURNAL Facility parameters must be set for lockout after 3 attempts.'
  desc 'By limiting the number of failed logon attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute-force attacks, is reduced. Limits are imposed by locking the account.'
  desc 'check', 'Examine VM:Secure Security Config File.

If there is no Journal record this is a finding.

If the Journal record has a maximum consecutive invalid password attempts set to 3, this is not a finding.

Note: The "warning" setting may be determined by the site but must be 3 or less.

Example:
JOURNAL 3 3'
  desc 'fix', 'Edit the SECURITY CONFIG file:

vmsecure config security

Configure a JOURNAL record in the SECURITY CONFIG file as follows:

JOURNAL 3 3

Note: The "warning" setting may be determined by the site but must be 3 or less.'
  impact 0.5
  ref 'DPMS Target IBM zVM Using CA VMSecure'
  tag check_id: 'C-41111r649541_chk'
  tag severity: 'medium'
  tag gid: 'V-237901'
  tag rid: 'SV-237901r649543_rule'
  tag stig_id: 'IBMZ-VM-000045'
  tag gtitle: 'SRG-OS-000021-GPOS-00005'
  tag fix_id: 'F-41070r649542_fix'
  tag 'documentable'
  tag legacy: ['SV-93555', 'V-78849']
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']
end
