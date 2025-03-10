control 'SV-93553' do
  title 'The IBM z/VM JOURNALING LOGON parameter must be set for lockout after 3 attempts for 15 minutes.'
  desc 'By limiting the number of failed logon attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute-force attacks, is reduced. Limits are imposed by locking the account.'
  desc 'check', 'Display the System Configuration File.

If the “JOURNALING” statement is set to:

Facility ON
LOGON
Lockout after 3 attempts for 15 minutes, this is not a finding.
Note: Site may set Lockout value at 0, this will require system administrator action for reset.


Issue "QUERY JOURNAL" command.

If the response is as follows this is not a finding:

Journal: LOGON-on'
  desc 'fix', 'Configure the System Configuration “JOURNALING” statement to:

Facility ON
LOGON
Lockout after 3 attempts for 15 minutes or 0 if system administrator action is desired.'
  impact 0.5
  ref 'DPMS Target z/VM Using CA VM:Secure'
  tag check_id: 'C-78433r2_chk'
  tag severity: 'medium'
  tag gid: 'V-78847'
  tag rid: 'SV-93553r2_rule'
  tag stig_id: 'IBMZ-VM-000040'
  tag gtitle: 'SRG-OS-000021-GPOS-00005'
  tag fix_id: 'F-85597r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']
end
