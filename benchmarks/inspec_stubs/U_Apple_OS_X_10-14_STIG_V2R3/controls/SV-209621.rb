control 'SV-209621' do
  title 'The macOS system must be configured to prevent displaying password hints.'
  desc 'Password hints leak information about passwords in use and can lead to loss of confidentiality.'
  desc 'check', 'To check that password hints are disabled, run the following command:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep RetriesUntilHint

If the return is null or is not "RetriesUntilHint = 0", this is a finding.'
  desc 'fix', 'This setting is enforce using the "Login Window" Policy.'
  impact 0.5
  ref 'DPMS Target Apple OS X 10.14'
  tag check_id: 'C-9872r282345_chk'
  tag severity: 'medium'
  tag gid: 'V-209621'
  tag rid: 'SV-209621r610285_rule'
  tag stig_id: 'AOSX-14-003012'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-9872r282346_fix'
  tag 'documentable'
  tag legacy: ['SV-105111', 'V-95973']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
