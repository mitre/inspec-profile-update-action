control 'SV-257245' do
  title 'The macOS system must restrict the ability of individuals to write to external optical media.'
  desc 'External writeable media devices must be disabled for users. External optical media devices can be used to exfiltrate sensitive data if an approved data-loss prevention (DLP) solution is not installed.'
  desc 'check', 'Verify the macOS system is configured to disable writing to external optical media devices with the following command:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep "BurnSupport"

BurnSupport = off;

If "BurnSupport" is not set to "off" and is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding.'
  desc 'fix', 'Configure the macOS system to disable writing to external optical media devices by installing the "Restrictions Policy" configuration profile.'
  impact 0.3
  ref 'DPMS Target Apple macOS 13'
  tag check_id: 'C-60930r905366_chk'
  tag severity: 'low'
  tag gid: 'V-257245'
  tag rid: 'SV-257245r905368_rule'
  tag stig_id: 'APPL-13-005053'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-60871r905367_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
