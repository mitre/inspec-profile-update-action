control 'SV-251774' do
  title 'The Ivanti MobileIron Core server must configured to lock administrator accounts after three unsuccessful login attempts.'
  desc 'By limiting the number of failed login attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute forcing, is reduced. Limits are imposed by locking the account. 

Satisfies:FMT_SMF.1(2)b 
Reference:PP-MDM-431030'
  desc 'check', 'Verify the Ivanti MobileIron Core server has been configured to lock administrator accounts after three unsuccessful login attempts.

Log in to the Core Admin Console >> Settings >> Security >> Password Policy.
Verify "Number of Failed attempts" is set to "3".

If the Ivanti MobileIron Core server does not lock administrator accounts after three unsuccessful login attempts, this is a finding.'
  desc 'fix', 'Configure the Ivanti MobileIron Core server to lock administrator accounts after three unsuccessful login attempts.

Log in to the Core Admin Console >> Settings >> Security >> Password Policy.
Set "Number of Failed attempts" to "3".'
  impact 0.5
  ref 'DPMS Target Ivanti MobileIron Core MDM Server'
  tag check_id: 'C-55211r810434_chk'
  tag severity: 'medium'
  tag gid: 'V-251774'
  tag rid: 'SV-251774r810435_rule'
  tag stig_id: 'IMIC-11-008510'
  tag gtitle: 'SRG-APP-000345-UEM-000218'
  tag fix_id: 'F-55165r810432_fix'
  tag 'documentable'
  tag cci: ['CCI-002238']
  tag nist: ['AC-7 b']
end
