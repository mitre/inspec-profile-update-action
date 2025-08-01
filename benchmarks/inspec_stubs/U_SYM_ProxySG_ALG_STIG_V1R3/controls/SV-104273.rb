control 'SV-104273' do
  title 'Symantec ProxySG must implement load balancing to limit the effects of known and unknown types of denial-of-service (DoS) attacks.'
  desc 'If the network does not provide safeguards against DoS attacks, network resources will be unavailable to users. Load balancing provides service redundancy, which reduces the susceptibility of the ALG to many DoS attacks.

The ALG must be configured to prevent or mitigate the impact on network availability and traffic flow of DoS attacks that have occurred or are ongoing.

This requirement applies to the network traffic functionality of the device as it pertains to handling network traffic. Some types of attacks may be specialized to certain network technologies, functions, or services. For each technology, known and potential DoS attacks must be identified and solutions for each type implemented.

For detailed information, see the ProxySG Administration Guide, Chapter 39: Configuring Failover.'
  desc 'check', 'Verify that redundancy has been configured on the ProxySG.

1. Log on to the Web Management Console.
2. Browse to Configuration >> Network >> Advanced.
3. Select the "Failover" tab and Verify that entries are present and that they are "enabled".

If Symantec ProxySG does not implement load balancing to limit the effects of known and unknown types of DoS attacks, this is a finding.'
  desc 'fix', 'Configure redundancy on the ProxySG.

1. Log on to the Web Management Console.
2. Browse to Configuration >> Network >> Advanced.
3. Select the "Failover" tab and configure using the SSP requirements.'
  impact 0.5
  ref 'DPMS Target Symantec ProxySG ALG'
  tag check_id: 'C-93505r1_chk'
  tag severity: 'medium'
  tag gid: 'V-94319'
  tag rid: 'SV-104273r1_rule'
  tag stig_id: 'SYMP-AG-000530'
  tag gtitle: 'SRG-NET-000362-ALG-000120'
  tag fix_id: 'F-100435r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
