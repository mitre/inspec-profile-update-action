control 'SV-20027' do
  title 'An Intrusion Detection and Prevention System (IDPS) sensor must be deployed to monitor the network segment hosting web, application, and database servers.'
  desc 'Attacks can originate within the enclave boundary. Hence, deploying an IDPS on the network segment hosting web, application, and database servers is imperative. The servers are critical resource and the network segment hosting them will receive the most traffic within the enclave.  Deploying IDPS on this network is promotes defense-in-depth principles that will enable operations to detect attacks quickly and take corrective actions.'
  desc 'check', 'Review topology of the network segment hosting the web, application, and database servers. 

If this segment is not being monitored by an IDPS sensor, this is a finding.'
  desc 'fix', 'Implement an IDPS strategy to monitor the network segment hosting web, application, and database servers.'
  impact 0.5
  ref 'DPMS Target Network Infrastructure Policy'
  tag check_id: 'C-21126r3_chk'
  tag severity: 'medium'
  tag gid: 'V-18492'
  tag rid: 'SV-20027r2_rule'
  tag stig_id: 'NET-IDPS-018'
  tag gtitle: 'IDPS sensor is not monitoring Server Farm segments'
  tag fix_id: 'F-19914r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001097', 'CCI-001255', 'CCI-002668']
  tag nist: ['SC-7 a', 'SI-4 c 1', 'SI-4 (11)']
end
