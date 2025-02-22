control 'SV-214872' do
  title 'The macOS system must disable iCloud Keychain synchronization.'
  desc 'Requiring individuals to be authenticated with an individual authenticator prior to using a group authenticator allows for traceability of actions, as well as adding an additional level of protection of the actions that can be taken with group account knowledge.

'
  desc 'check', 'To view the setting for the iCloud Keychain Synchronization configuration, run the following command:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep allowCloudKeychainSync

If the output is null or not "allowCloudKeychainSync = 0" this is a finding.'
  desc 'fix', 'This setting is enforced using the "Restrictions" configuration profile.'
  impact 0.5
  ref 'DPMS Target Apple OS X 10.13'
  tag check_id: 'C-16072r397188_chk'
  tag severity: 'medium'
  tag gid: 'V-214872'
  tag rid: 'SV-214872r609363_rule'
  tag stig_id: 'AOSX-13-000558'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-16070r397189_fix'
  tag satisfies: ['SRG-OS-000095-GPOS-00049', 'SRG-OS-000370-GPOS-00155']
  tag 'documentable'
  tag legacy: ['SV-96337', 'V-81623']
  tag cci: ['CCI-000381', 'CCI-001774']
  tag nist: ['CM-7 a', 'CM-7 (5) (b)']
end
