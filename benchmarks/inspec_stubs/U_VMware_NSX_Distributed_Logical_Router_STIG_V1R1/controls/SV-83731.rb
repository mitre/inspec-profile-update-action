control 'SV-83731' do
  title 'The NSX Distributed Logical Router must be configured so inactive router interfaces are disabled.'
  desc 'An inactive interface is rarely monitored or controlled and may expose a network to an undetected attack on that interface. Unauthorized personnel with access to the communication facility could gain access to a router by connecting to a configured interface that is not in use.'
  desc 'check', 'Verify there are no inactive router interfaces enabled.

Log onto vSphere Web Client with credentials authorized for administration.

Navigate and select Networking and Security >> "NSX Edges" tab on the left-side menu.

Double-click the EdgeID.

Click on the "Manage" tab on the top of the new screen, then Settings on the far left >> Interfaces >> Check the "Status" column for the associated interface.

If any inactive router interfaces are not disabled, this is a finding.'
  desc 'fix', 'Log onto vSphere Web Client with credentials authorized for administration.

Navigate and select Networking and Security >> select the "NSX Edges" tab on the left-side menu.

Double-click the EdgeID.

Click on the "Manage" tab on the top of the new screen then Settings on the far left >> Interfaces.

For interfaces that are not in use, highlight the interface and click the pencil icon.

Move the radio button next to "Connectivity Status" to "Disconnected".'
  impact 0.5
  ref 'DPMS Target VMware NSX 6 RTR'
  tag check_id: 'C-69567r1_chk'
  tag severity: 'medium'
  tag gid: 'V-69127'
  tag rid: 'SV-83731r1_rule'
  tag stig_id: 'VNSX-RT-000005'
  tag gtitle: 'SRG-NET-000019-RTR-000007'
  tag fix_id: 'F-75313r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
