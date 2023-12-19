control 'SV-86153' do
  title 'In the event the authentication server is unavailable, there must be one local account of last resort.'
  desc "Authentication for administrative (privileged-level) access to the device is required at all times. An account can be created on the device's local database for use in an emergency, such as when the authentication server is down or connectivity between the device and the authentication server is not operable. This account is also referred to as the account of last resort since the emergency administration account is strictly intended to be used only as a last resort and immediate administrative access is absolutely necessary.

The number of emergency administration accounts is restricted to at least one, but no more than operationally required as determined by the ISSO. The emergency administration account logon credentials must be stored in a sealed envelope and kept in a safe."
  desc 'check', 'Verify the "root" (or its equivalent, renamed account) is listed in the password configuration files.

If the "root" account is not listed in the password configuration files, this is a finding.'
  desc 'fix', 'Configure the "root" account as the local account of last resort. 

Disable the "ssgconfig" account by destroying its password and making the login shell "/sbin/nologin".'
  impact 0.5
  ref 'DPMS Target CA API Gateway NDM'
  tag check_id: 'C-71901r1_chk'
  tag severity: 'medium'
  tag gid: 'V-71529'
  tag rid: 'SV-86153r1_rule'
  tag stig_id: 'CAGW-DM-000150'
  tag gtitle: 'SRG-APP-000148-NDM-000346'
  tag fix_id: 'F-77849r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001358', 'CCI-002111']
  tag nist: ['AC-2 (7) (a)', 'AC-2 a']
end
