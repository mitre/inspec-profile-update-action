control 'SV-216112' do
  title 'Login services for serial ports must be disabled.'
  desc 'Login services should not be enabled on any serial ports that are not strictly required to support the mission of the system. This action can be safely performed even when console access is provided using a serial port.'
  desc 'check', 'Determine if terminal login services are disabled.

# svcs -Ho state svc:/system/console-login:terma
# svcs -Ho state svc:/system/console-login:termb

If the system/console-login services are not "disabled", this is a finding.'
  desc 'fix', 'The Service Operator profile is required.

Disable serial terminal services.

# pfexec svcadm disable svc:/system/console-login:terma
# pfexec svcadm disable svc:/system/console-login:termb'
  impact 0.5
  ref 'DPMS Target Solaris 11 X86'
  tag check_id: 'C-17350r372718_chk'
  tag severity: 'medium'
  tag gid: 'V-216112'
  tag rid: 'SV-216112r603268_rule'
  tag stig_id: 'SOL-11.1-040310'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-17348r372719_fix'
  tag 'documentable'
  tag legacy: ['V-48087', 'SV-60959']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
