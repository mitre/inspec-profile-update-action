control 'SV-88683' do
  title 'The Cisco IOS XE router must have a single local account that will only be used as an account of last resort with full access to the network device.'
  desc "Authentication for administrative (privileged level) access to the device is required at all times. An account can be created on the device's local database for use in an emergency, such as when the authentication server is down or connectivity between the device and the authentication server is not operable. This account is also referred to as the account of last resort since the emergency administration account is strictly intended to be used only as a last resort and immediate administrative access is absolutely necessary.

The number of emergency administration accounts is restricted to at least one, but no more than operationally required as determined by the ISSO. The emergency administration account logon credentials must be stored in a sealed envelope and kept in a safe."
  desc 'check', 'Verify that there is one local account configured on the Cisco IOS XE router.

The configuration should look similar to the example below:

username <username> privilege 15 password <password string>

If there is not a local account configured, this is a finding. 

If there is more than one local account configured, this is a finding.'
  desc 'fix', 'If there is more than one local account, delete the additional account by using the NO form of the username command.

If there is no local account, create one using the following username command:

<username> privilege 15 password <password>'
  impact 0.7
  ref 'DPMS Target Cisco IOS XE NDM'
  tag check_id: 'C-74095r3_chk'
  tag severity: 'high'
  tag gid: 'V-74009'
  tag rid: 'SV-88683r2_rule'
  tag stig_id: 'CISR-ND-000049'
  tag gtitle: 'SRG-APP-000148-NDM-000346'
  tag fix_id: 'F-80551r3_fix'
  tag 'documentable'
  tag cci: ['CCI-001358', 'CCI-002111']
  tag nist: ['AC-2 (7) (a)', 'AC-2 a']
end
