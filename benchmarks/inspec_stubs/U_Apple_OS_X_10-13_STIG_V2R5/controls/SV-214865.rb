control 'SV-214865' do
  title 'The macOS system must disable the Touch ID feature.'
  desc 'The Touch ID feature permits users to add additional fingerprints to unlock the host. These fingerprints may be for the user or anyone else. Because unauthorized users may gain access to the system, the use of Touch ID must be limited.'
  desc 'check', 'To view the setting for Touch ID configuration, run the following command:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep allowFingerprintForUnlock

If the output is null, not "allowFingerprintForUnlock = 0" this is a finding.'
  desc 'fix', 'This setting is enforced using the "Restrictions" configuration profile.'
  impact 0.5
  ref 'DPMS Target Apple OS X 10.13'
  tag check_id: 'C-16065r397167_chk'
  tag severity: 'medium'
  tag gid: 'V-214865'
  tag rid: 'SV-214865r609363_rule'
  tag stig_id: 'AOSX-13-000551'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-16063r397168_fix'
  tag 'documentable'
  tag legacy: ['SV-96323', 'V-81609']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
