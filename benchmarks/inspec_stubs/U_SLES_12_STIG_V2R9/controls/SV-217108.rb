control 'SV-217108' do
  title 'The SUSE operating system must utilize vlock to allow for session locking.'
  desc 'A session lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not want to log out because of the temporary nature of the absence.

The session lock is implemented at the point where session activity can be determined.

Regardless of where the session lock is determined and implemented, once invoked, the session lock must remain in place until the user reauthenticates. No other activity aside from reauthentication must unlock the system.

'
  desc 'check', 'Check that the SUSE operating system has the "vlock" package installed by running the following command: 

# zypper se -i --provides vlock 

If the command outputs "no matching items found", this is a finding.'
  desc 'fix', 'Allow users to lock the console by installing the "kbd" package using zypper:

# sudo zypper install kbd'
  impact 0.3
  ref 'DPMS Target SUSE Linux Enterprise Server 12'
  tag check_id: 'C-36357r602672_chk'
  tag severity: 'low'
  tag gid: 'V-217108'
  tag rid: 'SV-217108r603262_rule'
  tag stig_id: 'SLES-12-010070'
  tag gtitle: 'SRG-OS-000028-GPOS-00009'
  tag fix_id: 'F-36320r602673_fix'
  tag satisfies: ['SRG-OS-000028-GPOS-00009', 'SRG-OS-000030-GPOS-00011', 'SRG-OS-000031-GPOS-00012']
  tag 'documentable'
  tag legacy: ['V-77059', 'SV-91755']
  tag cci: ['CCI-000060', 'CCI-000056', 'CCI-000058']
  tag nist: ['AC-11 (1)', 'AC-11 b', 'AC-11 a']
end
