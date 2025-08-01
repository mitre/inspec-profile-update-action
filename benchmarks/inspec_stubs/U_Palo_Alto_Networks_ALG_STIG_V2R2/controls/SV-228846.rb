control 'SV-228846' do
  title 'The Palo Alto Networks security platform must terminate communications sessions after 15 minutes of inactivity.'
  desc 'Idle sessions can accumulate, leading to an exhaustion of memory in network elements processing traffic flows.
Note that the 15 minute period is a maximum value; Administrators can choose shorter timeout values to account for system- or network-specific requirements.

On a Palo Alto Networks security platform,  a session is defined by two uni-directional flows, each uniquely identified by a 6-tuple key: source-address, destination-address, source-port, destination-port, protocol, and security-zone.  Besides the six attributes that identify a session, each session has few more notable identifiers: end hosts - the source IP and destination IP which will be marked as client(source IP) and server(destination IP) and flow direction - each session is bi-directional and is identified by a two uni-directional flows, the first flow is client-to-server(c2s) and the returning flow is server-to-client(s2c).

Sessions between endpoints are kept active by either normal traffic or by keepalive messages (also sometimes referred to as heartbeat messages).  On the Palo Alto Networks security platform, the session timeout period is the time (seconds) required for the application to time out due to inactivity.  Session timeouts are configured globally and on a per-application basis.  When configured, timeouts for an application override the global TCP or UDP session timeouts.'
  desc 'check', 'To check global values:
Go to Device >> Setup >> Session
In the "Session Timeouts" pane, if the TCP field has a value of greater than "900", this is a finding.

Obtain the list of authorized applications for the system or network.
To check application-specific values:
Go to Objects >> Applications
Select, in turn, each authorized application.
In the "Application" window, in the "Options" pane, view the "TCP" and "UDP Timeout" fields, if the value is greater than "900", this is a finding.

Many applications will not have one of these two fields.'
  desc 'fix', 'To configure the global values:
Go to Device >> Setup >> Session
In the "Session Timeouts" pane, select the "Edit" icon (the gear symbol in the upper-right corner of the pane).
In the "TCP" field, enter "900".
Select "OK".

To configure application-specific values:
Go to Objects >> Applications
Select an application name to view additional details about the application.
To search for a specific application, enter the "application name" or "description" in the "Search" field.
In the "Application" window, in the "Options" pane, in the "TCP Timeout" field, select "Customize".
In the Application specific window, in the "TCP" and "UDP Timeout" fields, enter "900" if the existing value is greater than "900".   Many applications will not have one of these two fields.
Select "OK".
Commit changes by selecting "Commit" in the upper-right corner of the screen.
Select "OK" when the confirmation dialog appears.'
  impact 0.5
  ref 'DPMS Target Palo Alto Networks ALG'
  tag check_id: 'C-31081r513833_chk'
  tag severity: 'medium'
  tag gid: 'V-228846'
  tag rid: 'SV-228846r557387_rule'
  tag stig_id: 'PANW-AG-000052'
  tag gtitle: 'SRG-NET-000213-ALG-000107'
  tag fix_id: 'F-31058r513834_fix'
  tag 'documentable'
  tag legacy: ['V-62575', 'SV-77065']
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']
end
