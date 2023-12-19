control 'SV-257231' do
  title 'The macOS system must be configured to prevent displaying password hints.'
  desc 'Password hints leak information about passwords in use and can lead to loss of confidentiality.'
  desc 'check', 'Verify the macOS system is configured to prevent displaying passwords hints with the following command:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep "RetriesUntilHint"

RetriesUntilHint = 0;

If "RetriesUntilHint" is not set to "0", this is a finding.'
  desc 'fix', 'Configure the macOS system to prevent displaying password hints by installing the "Login Window Policy" configuration profile.'
  impact 0.5
  ref 'DPMS Target Apple macOS 13'
  tag check_id: 'C-60916r905324_chk'
  tag severity: 'medium'
  tag gid: 'V-257231'
  tag rid: 'SV-257231r905326_rule'
  tag stig_id: 'APPL-13-003012'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-60857r905325_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
