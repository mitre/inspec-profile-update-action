control 'SV-233030' do
  title 'The container platform must enforce approved authorizations for controlling the flow of information between interconnected systems and services based on organization-defined information flow control policies.'
  desc 'Controlling information flow between the container platform components and container user services instantiated by the container platform must enforce organization-defined information flow policies. Example methods for information flow control are: using labels for containers to segregate services; user permissions and roles to limit what user services are available to each user; controlling the user the services are able to execute as; and limiting inter-container network traffic and the resources containers can consume.'
  desc 'check', 'Review the container platform configuration to determine if organization-defined information flow controls are implemented. 

If information flow controls are not implemented, this is a finding.'
  desc 'fix', 'Configure the container platform to implement organization-defined information flow controls.'
  impact 0.5
  ref 'DPMS Target Container Platform'
  tag check_id: 'C-35966r600577_chk'
  tag severity: 'medium'
  tag gid: 'V-233030'
  tag rid: 'SV-233030r600579_rule'
  tag stig_id: 'SRG-APP-000039-CTR-000110'
  tag gtitle: 'SRG-APP-000039'
  tag fix_id: 'F-35934r600578_fix'
  tag 'documentable'
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
