control 'SV-225210' do
  title 'The macOS system must be configured to prevent displaying password hints.'
  desc 'Password hints leak information about passwords in use and can lead to loss of confidentiality.'
  desc 'check', 'To check that password hints are disabled, run the following command:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep RetriesUntilHint

If the return is null or is not "RetriesUntilHint = 0", this is a finding.'
  desc 'fix', 'This setting is enforce using the "Login Window" Policy.'
  impact 0.5
  ref 'DPMS Target Apple OS X 10.15'
  tag check_id: 'C-26909r485794_chk'
  tag severity: 'medium'
  tag gid: 'V-225210'
  tag rid: 'SV-225210r610901_rule'
  tag stig_id: 'AOSX-15-003012'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-26897r467799_fix'
  tag 'documentable'
  tag legacy: ['V-102839', 'SV-111801']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
