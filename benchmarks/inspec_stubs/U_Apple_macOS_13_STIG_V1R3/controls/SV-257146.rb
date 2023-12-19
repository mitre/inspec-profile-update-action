control 'SV-257146' do
  title 'The macOS system must be configured to lock the user session when a smart token is removed.'
  desc 'A session lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not want to log out because of the temporary nature of the absence.

The session lock is implemented at the point where session activity can be determined. Rather than be forced to wait for a period of time to expire before the user session can be locked, operating systems must provide users with the ability to manually invoke a session lock so users may secure their session should they need to temporarily vacate the immediate physical vicinity.'
  desc 'check', 'Verify the macOS system is configured to lock the user session when a smart token is removed with the following command:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep "tokenRemovalAction"

tokenRemovalAction = 1;

If there is no result, or if "tokenRemovalAction" is not set to "1", this is a finding.'
  desc 'fix', 'Configure the macOS system to lock the user session when a smart token is removed by installing the "Smart Card Policy" configuration profile.

Note: To ensure continued access to the operating system, consult the supplemental guidance provided with the STIG before applying the "Smart Card Policy".'
  impact 0.5
  ref 'DPMS Target Apple macOS 13'
  tag check_id: 'C-60831r905069_chk'
  tag severity: 'medium'
  tag gid: 'V-257146'
  tag rid: 'SV-257146r905071_rule'
  tag stig_id: 'APPL-13-000005'
  tag gtitle: 'SRG-OS-000030-GPOS-00011'
  tag fix_id: 'F-60772r905070_fix'
  tag 'documentable'
  tag cci: ['CCI-000058']
  tag nist: ['AC-11 a']
end
