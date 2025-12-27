control 'SV-233221' do
  title 'The container platform runtime must maintain separate execution domains for each container by assigning each container a separate address space.'
  desc 'Container namespace access is limited upon runtime execution. Each container is a distinct process so that communication between containers is performed in a manner controlled through security policies that limits the communication so one container cannot modify another container. Different groups of containers with different security needs should be deployed in separate namespaces as a first level of isolation.

Namespaces are a key boundary for network policies, orchestrator access control restrictions, and other important security controls. Separating workloads into namespaces can help contain attacks and limit the impact of mistakes or destructive actions by authorized users.'
  desc 'check', 'Review container platform runtime documentation and configuration is maintaining a separate execution domain for each executing process. Different groups of applications, and services with different security needs, should be deployed in separate namespaces as a first level of isolation. 

If container platform runtime is not configured to execute processes in separate domains and namespaces, this is a finding. 

If namespaces use defaults, this is a finding.'
  desc 'fix', 'Deploy a container platform runtime capable of maintaining a separate execution domain and namespace for each executing process. Create a namespace for each containers, defining them as logical groups.'
  impact 0.5
  ref 'DPMS Target Container Platform'
  tag check_id: 'C-36157r599656_chk'
  tag severity: 'medium'
  tag gid: 'V-233221'
  tag rid: 'SV-233221r599657_rule'
  tag stig_id: 'SRG-APP-000431-CTR-001065'
  tag gtitle: 'SRG-APP-000431'
  tag fix_id: 'F-36125r599300_fix'
  tag 'documentable'
  tag cci: ['CCI-002530']
  tag nist: ['SC-39']
end
