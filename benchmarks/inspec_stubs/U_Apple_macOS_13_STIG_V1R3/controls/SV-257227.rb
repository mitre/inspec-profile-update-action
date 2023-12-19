control 'SV-257227' do
  title 'The macOS system must enforce a 60-day maximum password lifetime restriction.'
  desc 'Any password, no matter how complex, can eventually be cracked. Therefore, passwords need to be changed periodically.

One method of minimizing this risk is to use complex passwords and periodically change them. If the operating system does not limit the lifetime of passwords and force users to change their passwords, there is the risk that the operating system passwords could be compromised.'
  desc 'check', 'Verify the macOS system is configured to enforce a 60-day maximum password lifetime with the following command:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep "maxPINAgeInDays"

maxPINAgeInDays = 60;

If "maxPINAgeInDays" is set a value greater than "60", this is a finding.'
  desc 'fix', 'Configure the macOS system to require the enforcement of a 60-day maximum password lifetime by installing the "Passcode Policy" configuration profile.'
  impact 0.5
  ref 'DPMS Target Apple macOS 13'
  tag check_id: 'C-60912r905312_chk'
  tag severity: 'medium'
  tag gid: 'V-257227'
  tag rid: 'SV-257227r905314_rule'
  tag stig_id: 'APPL-13-003008'
  tag gtitle: 'SRG-OS-000076-GPOS-00044'
  tag fix_id: 'F-60853r905313_fix'
  tag 'documentable'
  tag cci: ['CCI-000199']
  tag nist: ['IA-5 (1) (d)']
end
