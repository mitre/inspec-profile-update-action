control 'SV-202008' do
  title 'The network device must be configured to enable network administrators to directly initiate a session lock.'
  desc 'A session lock is a temporary network device or administrator-initiated action taken when the administrator stops work but does not log out of the network device.  Rather than being forced to wait for a period of time to expire before the management session can be locked, network management consoles need to provide administrators with the ability to manually invoke a session lock so they may secure their management session should the need arise for them to temporarily vacate the immediate physical vicinity of the management workstation.  Once invoked, the session lock shall remain in place until the administrator re-authenticates. No other system activity aside from re-authentication shall unlock the management session.

The session lock is implemented at the point where session activity can be determined. This is typically at the operating system-level, but may be at the application-level. The session lock is initiated and controlled by either the client application or the workstation being used to access a network element.  Many terminal emulation clients implement this capability through software flow control or XOFF/XON flow control.

If this capability is not available, administrators must terminate all management sessions before leaving their management console or workstation.  This includes closing any views or windows from those sessions.'
  desc 'check', 'Directly observe the management application or the console; if an administrator cannot directly initiate a session lock from either the management application or the console, this is a finding.'
  desc 'fix', 'This is an intrinsic capability of the client application or the console.  Many terminal emulation clients implement this capability through software flow control or XOFF/XON flow control.'
  impact 0.5
  ref 'DPMS Target Network Device Management'
  tag check_id: 'C-2134r381563_chk'
  tag severity: 'medium'
  tag gid: 'V-202008'
  tag rid: 'SV-202008r395451_rule'
  tag stig_id: 'SRG-APP-000004-NDM-000203'
  tag gtitle: 'SRG-APP-000004'
  tag fix_id: 'F-2135r381564_fix'
  tag 'documentable'
  tag legacy: ['SV-69279', 'V-55033']
  tag cci: ['CCI-000058']
  tag nist: ['AC-11 a']
end
