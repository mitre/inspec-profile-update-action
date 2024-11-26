control 'SV-251777' do
  title "The Ivanti MobileIron Core server must be configured to lock an administrator's account for at least 15 minutes after the account has been locked because the maximum number of unsuccessful login attempts has been exceeded."
  desc 'By limiting the number of failed login attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute forcing, is reduced. Limits are imposed by locking the account. 

Satisfies:FMT_SMF.1(2)b 
Reference:PP-MDM-431030'
  desc 'check', %q(Verify the Ivanti MobileIron Core server has been configured to lock an administrator's account for at least 15 minutes after the account has been locked because the maximum number of unsuccessful login attempts has been exceeded.

Log in to the Core Admin Console >> Settings >> Security >> Password Policy.
Verify "Auto-Lock Time" is set to 15 minutes (900 seconds).

If the Ivanti MobileIron Core server does not lock an administrator's account for at least 15 minutes after the account has been locked because the maximum number of unsuccessful login attempts has been exceeded, this is a finding.)
  desc 'fix', %q(Configure the Ivanti MobileIron Core server to lock an administrator's account for at least 15 minutes after the account has been locked because the maximum number of unsuccessful login attempts has been exceeded.

Log in to the Core Admin Console >> Settings >> Security >> Password Policy.
Set "Auto-Lock Time" to 15 minutes (900 seconds).)
  impact 0.5
  ref 'DPMS Target Ivanti MobileIron Core MDM Server'
  tag check_id: 'C-55214r810437_chk'
  tag severity: 'medium'
  tag gid: 'V-251777'
  tag rid: 'SV-251777r810439_rule'
  tag stig_id: 'IMIC-11-008520'
  tag gtitle: 'SRG-APP-000345-UEM-000218'
  tag fix_id: 'F-55168r810438_fix'
  tag 'documentable'
  tag cci: ['CCI-002238']
  tag nist: ['AC-7 b']
end
