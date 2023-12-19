control 'SV-219304' do
  title 'The Ubuntu operating system must be configured for users to directly initiate a session lock for all connection types.'
  desc 'A session lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not want to log out because of the temporary nature of the absence.

The session lock is implemented at the point where session activity can be determined. Rather than be forced to wait for a period of time to expire before the user session can be locked, the Ubuntu operating system need to provide users with the ability to manually invoke a session lock so users may secure their session should the need arise for them to temporarily vacate the immediate physical vicinity.

'
  desc 'check', %q(Verify the Ubuntu operating system has the 'vlock' package installed, by running the following command:

# dpkg -l | grep vlock

If "vlock" is not installed, this is a finding.)
  desc 'fix', 'Install the "vlock" (if it is not already installed) package by running the following command:

# sudo apt-get install vlock'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 18.04 LTS'
  tag check_id: 'C-21029r305240_chk'
  tag severity: 'medium'
  tag gid: 'V-219304'
  tag rid: 'SV-219304r610963_rule'
  tag stig_id: 'UBTU-18-010403'
  tag gtitle: 'SRG-OS-000030-GPOS-00011'
  tag fix_id: 'F-21028r305241_fix'
  tag satisfies: ['SRG-OS-000030-GPOS-00011', 'SRG-OS-000031-GPOS-00012']
  tag 'documentable'
  tag legacy: ['V-100831', 'SV-109935']
  tag cci: ['CCI-000058', 'CCI-000060']
  tag nist: ['AC-11 a', 'AC-11 (1)']
end
