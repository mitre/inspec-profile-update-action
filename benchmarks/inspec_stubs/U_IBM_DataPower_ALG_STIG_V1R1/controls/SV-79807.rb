control 'SV-79807' do
  title 'The DataPower Gateway must not use 0.0.0.0 as a listening IP address for any service.'
  desc 'Using 0.0.0.0 as a listening address allows all interfaces to receive traffic for the service. This creates an unnecessary exposure when services are configured to listen on this address.'
  desc 'check', 'Go to Default domain.

Click Status >> Main >> Active Services >> Click Show All Domains.

Review IP addresses assigned to active services. If any list 0.0.0.0, this is a finding.'
  desc 'fix', 'Log on to each active domain. 

Click Objects >> Protocol Handlers >> HTTP Front Side Handlers.

Click on the name of any Handler listed that uses the IP Address of 0.0.0.0.

Change the IP Address >> Click Apply.

Click Objects >> Protocol Handlers >> HTTPS Front Side Handlers.

Click on the name of any Handler listed that uses the IP Address of 0.0.0.0.

Change the IP Address >> Click Apply >> Click Save Configuration.'
  impact 0.5
  ref 'DPMS Target IBM DataPower XI52 ALG'
  tag check_id: 'C-65945r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65317'
  tag rid: 'SV-79807r1_rule'
  tag stig_id: 'WSDP-AG-000151'
  tag gtitle: 'SRG-NET-000364-ALG-000122'
  tag fix_id: 'F-71257r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002403']
  tag nist: ['SC-7 (11)']
end
