control 'SV-93607' do
  title 'The IBM z/VM TCP/IP PENDINGCONNECTIONLIMIT statement must be properly configured.'
  desc 'DoS is a condition when a resource is not available for legitimate users. When this occurs, the organization either cannot accomplish its mission or must operate at degraded capacity.

Managing excess capacity ensures that sufficient capacity is available to counter flooding attacks. Employing increased capacity and service redundancy may reduce the susceptibility to some DoS attacks. Managing excess capacity may include, for example, establishing selected usage priorities, quotas, or partitioning.

The PENDINGCONNECTIONLIMIT statement defines the maximum number of half-open connections that are allowed at any given time. When a new half-open connection causes this limit to be exceeded, a random current half-open connection is dropped and a SynFlood denial-of-service attack is declared.'
  desc 'check', 'Examine the “TCP/IP” configuration file.

If there is no “PENDINGCONNECTIONLIMIT” statement, this is a finding.'
  desc 'fix', 'Configure the “PENDINGCONNECTIONLIMIT” statement with a value that is less than the “TCBPOOLSIZE”.'
  impact 0.5
  ref 'DPMS Target z/VM Using CA VM:Secure'
  tag check_id: 'C-78487r1_chk'
  tag severity: 'medium'
  tag gid: 'V-78901'
  tag rid: 'SV-93607r1_rule'
  tag stig_id: 'IBMZ-VM-000740'
  tag gtitle: 'SRG-OS-000142-GPOS-00071'
  tag fix_id: 'F-85651r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001095']
  tag nist: ['SC-5 (2)']
end
