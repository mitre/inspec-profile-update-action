control 'SV-233029' do
  title 'The container platform must enforce approved authorizations for controlling the flow of information within the container platform based on organization-defined information flow control policies.'
  desc 'Controlling information flow between the container platform components and container user services instantiated by the container platform must enforce organization-defined information flow policies. Example methods for information flow control are using labels and separate namespace for containers to segregate services; user permissions and roles to limit what user services are available to each user; controlling the user the services are able to execute as; and limiting inter-container network traffic and the resources containers can consume.'
  desc 'check', 'Review the container platform to determine if approved authorizations for controlling the flow of information within the container platform based on organization-defined information flow control policies is being enforced. 

If the organization-defined information flow policies are not being enforced, this is a finding.'
  desc 'fix', 'Configure the container platform to enforce approved authorizations for controlling the flow of information within the container platform based on organization-defined information flow control policies.'
  impact 0.5
  ref 'DPMS Target Container Platform'
  tag check_id: 'C-35965r601604_chk'
  tag severity: 'medium'
  tag gid: 'V-233029'
  tag rid: 'SV-233029r601605_rule'
  tag stig_id: 'SRG-APP-000038-CTR-000105'
  tag gtitle: 'SRG-APP-000038'
  tag fix_id: 'F-35933r600575_fix'
  tag 'documentable'
  tag cci: ['CCI-001368']
  tag nist: ['AC-4']
end
