control 'SV-237926' do
  title 'The IBM z/VM TCP/IP PERSISTCONNECTIONLIMIT statement must be properly configured.'
  desc 'DoS is a condition when a resource is not available for legitimate users. When this occurs, the organization either cannot accomplish its mission or must operate at degraded capacity.

Managing excess capacity ensures that sufficient capacity is available to counter flooding attacks. Employing increased capacity and service redundancy may reduce the susceptibility to some DoS attacks. Managing excess capacity may include, for example, establishing selected usage priorities, quotas, or partitioning.

The PERSISTCONNECTIONLIMIT statement defines the maximum number of connections in TCP persist state at any given time. When a new connection in persist state causes this limit to be exceeded, the oldest current connection in persist state is dropped and a ZeroWin denial-of-service attack is declared.'
  desc 'check', 'Examine the “TCP/IP” configuration file.

If there is no “PERSISTCONNECTIONLIMIT” statement, this is a finding.'
  desc 'fix', 'Configure the “PERSISTCONNECTIONLIMIT” statement with a value that is less than the “TCBPOOLSIZE”.'
  impact 0.5
  ref 'DPMS Target IBM zVM Using CA VMSecure'
  tag check_id: 'C-41136r649616_chk'
  tag severity: 'medium'
  tag gid: 'V-237926'
  tag rid: 'SV-237926r649618_rule'
  tag stig_id: 'IBMZ-VM-000730'
  tag gtitle: 'SRG-OS-000142-GPOS-00071'
  tag fix_id: 'F-41095r649617_fix'
  tag 'documentable'
  tag legacy: ['SV-93605', 'V-78899']
  tag cci: ['CCI-001095']
  tag nist: ['SC-5 (2)']
end
