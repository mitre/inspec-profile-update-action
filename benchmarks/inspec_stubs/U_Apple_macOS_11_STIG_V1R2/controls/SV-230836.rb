control 'SV-230836' do
  title 'The macOS system must be configured to prevent displaying password hints.'
  desc 'Password hints leak information about passwords in use and can lead to loss of confidentiality.'
  desc 'check', 'To check that password hints are disabled, run the following command:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep RetriesUntilHint

If the return is null or is not "RetriesUntilHint = 0", this is a finding.'
  desc 'fix', 'This setting is enforce using the "Login Window" Policy.'
  impact 0.5
  ref 'DPMS Target Apple macOS 11'
  tag check_id: 'C-33781r607395_chk'
  tag severity: 'medium'
  tag gid: 'V-230836'
  tag rid: 'SV-230836r599842_rule'
  tag stig_id: 'APPL-11-003012'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-33754r607396_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
