control 'SV-233122' do
  title 'The container platform runtime must fail to a secure state if system initialization fails, shutdown fails, or aborts fail.'
  desc 'The container platform offers services for container image orchestration and services for users. If any of these services were to fail into an insecure state, security measures for user and data separation and image instantiation could become absent. In addition, audit log protections could be relaxed allowing for investigation of what occurred could be lost. To protect services and data, it is important for the container platform to fail to a secure state if the container platform registry initialization fails, shutdown fails, or aborts fail.'
  desc 'check', 'Review documentation and configuration to determine if the container platform runtime fails to a secure state if system initialization fails, shutdown fails, or aborts fail. 

If the container platform runtime cannot be configured to fail securely, this is a finding.'
  desc 'fix', 'Configure the container platform runtime to fail to a secure state if system initialization fails, shutdown fails, or aborts fail.'
  impact 0.5
  ref 'DPMS Target Container Platform'
  tag check_id: 'C-36058r601746_chk'
  tag severity: 'medium'
  tag gid: 'V-233122'
  tag rid: 'SV-233122r601749_rule'
  tag stig_id: 'SRG-APP-000225-CTR-000570'
  tag gtitle: 'SRG-APP-000225'
  tag fix_id: 'F-36026r600854_fix'
  tag 'documentable'
  tag cci: ['CCI-001190']
  tag nist: ['SC-24']
end
