control 'SV-214933' do
  title 'The macOS system must be configured to lock the user session when a smart token is removed.'
  desc 'A session lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not want to log out because of the temporary nature of the absence.

The session lock is implemented at the point where session activity can be determined. Rather than be forced to wait for a period of time to expire before the user session can be locked, operating systems need to provide users with the ability to manually invoke a session lock so users may secure their session should they need to temporarily vacate the immediate physical vicinity.'
  desc 'check', 'To check if support for session locking with removal of a token is enabled, run the following command:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep "tokenRemovalAction = 1;"

If there is no result, this is a finding.'
  desc 'fix', 'This is now in the smartcard payload.
<key>tokenRemovalAction</key>
                  <integer>1</integer>'
  impact 0.5
  ref 'DPMS Target Apple OS X 10.13'
  tag check_id: 'C-16133r397371_chk'
  tag severity: 'medium'
  tag gid: 'V-214933'
  tag rid: 'SV-214933r609363_rule'
  tag stig_id: 'AOSX-13-030014'
  tag gtitle: 'SRG-OS-000030-GPOS-00011'
  tag fix_id: 'F-16131r397372_fix'
  tag 'documentable'
  tag legacy: ['SV-96461', 'V-81747']
  tag cci: ['CCI-000058']
  tag nist: ['AC-11 a']
end
