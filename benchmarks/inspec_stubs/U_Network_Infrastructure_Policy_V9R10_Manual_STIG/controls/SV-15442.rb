control 'SV-15442' do
  title 'An Out-of-Band (OOB) management network must be deployed for MAC I systems or 24x7 personnel must have console access for device management.'
  desc 'From an architectural point of view, providing Out-Of-Band (OOB) management of network systems is the best first step in any management strategy. No production traffic resides on an out-of-band network. The biggest advantage to implementation of an OOB network is providing support and maintenance to the network that has become degraded or compromised.  During an outage or degradation period the in band management link may not be available.  The consequences of loss of availability of a MAC I system is unacceptable and could include the immediate and sustained loss of mission effectiveness.  Mission Assurance Category I systems require the most stringent protection measures.  Maintenance support for key IT assets must be available to respond 24x7 immediately upon failure.'
  desc 'check', 'Review the network topology and verify that an OOB network provides connectivity from the management network to all of the managed network elements. 

If an OOB network has not been deployed, verify that the network administrators have management access via the console to the managed network elements. 

If there is no OOB network or if network administrators do not have management access via the console to the managed network elements, this is a finding.'
  desc 'fix', 'The network administrator will manage devices via direct connection or access via OOB management network.'
  impact 0.5
  ref 'DPMS Target Network Infrastructure Policy'
  tag check_id: 'C-12907r2_chk'
  tag severity: 'medium'
  tag gid: 'V-14716'
  tag rid: 'SV-15442r2_rule'
  tag stig_id: 'NET1622'
  tag gtitle: 'Device management is not using an OOB network.'
  tag fix_id: 'F-14183r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
