control 'SV-209617' do
  title 'The macOS system must enforce a 60-day maximum password lifetime restriction.'
  desc 'Any password, no matter how complex, can eventually be cracked. Therefore, passwords need to be changed periodically.

One method of minimizing this risk is to use complex passwords and periodically change them. If the operating system does not limit the lifetime of passwords and force users to change their passwords, there is the risk that the operating system passwords could be compromised.'
  desc 'check', 'To check the currently applied policies for passwords and accounts, use the following command:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep maxPINAgeInDays

If "maxPINAgeInDays" is set a value greater than "60", this is a finding.'
  desc 'fix', 'This setting is enforced using the "Passcode Policy" configuration profile.'
  impact 0.5
  ref 'DPMS Target Apple OS X 10.14'
  tag check_id: 'C-9868r282333_chk'
  tag severity: 'medium'
  tag gid: 'V-209617'
  tag rid: 'SV-209617r610285_rule'
  tag stig_id: 'AOSX-14-003008'
  tag gtitle: 'SRG-OS-000076-GPOS-00044'
  tag fix_id: 'F-9868r282334_fix'
  tag 'documentable'
  tag legacy: ['SV-105103', 'V-95965']
  tag cci: ['CCI-000199']
  tag nist: ['IA-5 (1) (d)']
end
