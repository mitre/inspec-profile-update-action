control 'SV-214892' do
  title 'The macOS system must restrict the ability of individuals to use USB storage devices.'
  desc 'External hard drives, such as USB, must be disabled for users. USB hard drives are a potential vector for malware and can be used to exfiltrate sensitive data if an approved data-loss prevention (DLP) solution is not installed.'
  desc 'check', 'If an approved HBSS DCM/DLP solution is installed, this is not applicable.

To verify external USB drives are disabled, run the following command:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -A 3 harddisk-external

If the result is not “harddisk-external" = (
eject,
alert
);”, this is a finding.'
  desc 'fix', 'This setting is enforced using the "Restrictions Policy" configuration profile.'
  impact 0.5
  ref 'DPMS Target Apple OS X 10.13'
  tag check_id: 'C-16092r397248_chk'
  tag severity: 'medium'
  tag gid: 'V-214892'
  tag rid: 'SV-214892r609363_rule'
  tag stig_id: 'AOSX-13-000850'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-16090r397249_fix'
  tag 'documentable'
  tag legacy: ['SV-96377', 'V-81663']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
