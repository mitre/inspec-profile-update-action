control 'SV-209525' do
  title 'The macOS system must be configured to lock the user session when a smart token is removed.'
  desc 'A session lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not want to log out because of the temporary nature of the absence.

The session lock is implemented at the point where session activity can be determined. Rather than be forced to wait for a period of time to expire before the user session can be locked, operating systems need to provide users with the ability to manually invoke a session lock so users may secure their session should they need to temporarily vacate the immediate physical vicinity.'
  desc 'check', 'To check if support for session locking with removal of a token is enabled, run the following command:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep "tokenRemovalAction = 1;"

If there is no result, this is a finding.'
  desc 'fix', 'This setting is enforced using the "Smart Card Policy" configuration profile. 

Note: Before applying the "Smart Card Policy", the supplemental guidance provided with the STIG should be consulted to ensure continued access to the operating system.'
  impact 0.5
  ref 'DPMS Target Apple OS X 10.14'
  tag check_id: 'C-9776r282057_chk'
  tag severity: 'medium'
  tag gid: 'V-209525'
  tag rid: 'SV-209525r610285_rule'
  tag stig_id: 'AOSX-14-000005'
  tag gtitle: 'SRG-OS-000030-GPOS-00011'
  tag fix_id: 'F-9776r282058_fix'
  tag 'documentable'
  tag legacy: ['SV-104933', 'V-95795']
  tag cci: ['CCI-000058']
  tag nist: ['AC-11 a']
end
