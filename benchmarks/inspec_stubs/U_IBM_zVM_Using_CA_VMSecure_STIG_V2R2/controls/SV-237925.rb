control 'SV-237925' do
  title 'The IBM z/VM TCP/IP FOREIGNIPCONLIMIT statement must be properly configured.'
  desc 'DoS is a condition when a resource is not available for legitimate users. When this occurs, the organization either cannot accomplish its mission or must operate at degraded capacity.

Managing excess capacity ensures that sufficient capacity is available to counter flooding attacks. Employing increased capacity and service redundancy may reduce the susceptibility to some DoS attacks. Managing excess capacity may include, for example, establishing selected usage priorities, quotas, or partitioning.

Use the FOREIGNIPCONLIMIT statement to define the maximum number of connections that a foreign IP address is allowed to have open at the same time. If this value would be exceeded, an SSTRESS denial-of-service attack is declared.'
  desc 'check', 'Examine "TCP/IP" configuration file.

If there is no "FOREIGNIPCONLIMIT" statement, this is a finding.

If the "FOREIGNIPCONLIMIT" has a value of "0", this is a finding.'
  desc 'fix', 'Configure the "FOREIGNIPCONLIMIT" statement with a value specifying the maximum number of connections that a foreign IP address is allowed to have open at the same time.

The System Administrator should determine the proper value.'
  impact 0.5
  ref 'DPMS Target IBM zVM Using CA VMSecure'
  tag check_id: 'C-41135r858981_chk'
  tag severity: 'medium'
  tag gid: 'V-237925'
  tag rid: 'SV-237925r858983_rule'
  tag stig_id: 'IBMZ-VM-000720'
  tag gtitle: 'SRG-OS-000142-GPOS-00071'
  tag fix_id: 'F-41094r858982_fix'
  tag 'documentable'
  tag legacy: ['SV-93603', 'V-78897']
  tag cci: ['CCI-001095']
  tag nist: ['SC-5 (2)']
end
