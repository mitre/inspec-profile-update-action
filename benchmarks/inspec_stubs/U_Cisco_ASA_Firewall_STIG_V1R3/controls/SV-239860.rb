control 'SV-239860' do
  title 'The Cisco ASA must be configured to enable threat detection to mitigate risks of denial-of-service (DoS) attacks.'
  desc %q(A firewall experiencing a DoS attack will not be able to handle production traffic load. The high utilization and CPU caused by a DoS attack will also have an effect on control keep-alives and timers used for neighbor peering, resulting in route flapping and will eventually black-hole production traffic.

The device must be configured to contain and limit a DoS attack's effect on the device's resource utilization. The use of redundant components and load balancing are examples of mitigating "flood-type" DoS attacks through increased capacity.)
  desc 'check', 'NOTE: When operating the ASA in multi-context mode with a separate IDPS, threat detection cannot be enabled, and this check is Not Applicable.

Review the ASA configuration to determine if threat detection has been enabled.

threat-detection basic-threat

If the ASA has not been configured to enable threat detection to mitigate risks of DoS attacks, this is a finding.'
  desc 'fix', 'Configure threat detection as shown in the example below.

ASA(config)# threat-detection basic-threat'
  impact 0.5
  ref 'DPMS Target Cisco ASA Firewall'
  tag check_id: 'C-43093r863228_chk'
  tag severity: 'medium'
  tag gid: 'V-239860'
  tag rid: 'SV-239860r863229_rule'
  tag stig_id: 'CASA-FW-000150'
  tag gtitle: 'SRG-NET-000193-FW-000030'
  tag fix_id: 'F-43052r665865_fix'
  tag 'documentable'
  tag cci: ['CCI-001095']
  tag nist: ['SC-5 (2)']
end
