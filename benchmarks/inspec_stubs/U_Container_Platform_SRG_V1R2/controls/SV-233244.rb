control 'SV-233244' do
  title 'The container platform must provide system notifications to the system administrator and operational staff when anomalies in the operation of the organization-defined security functions are discovered.'
  desc 'If anomalies are not acted upon, security functions may fail to secure the container within the container platform runtime.

Security functions are responsible for enforcing the system security policy and supporting the isolation of code and data on which the protection is based. Security functionality includes, but is not limited to, establishing system accounts, configuring access authorizations (i.e., permissions, privileges), setting events to be audited, and setting intrusion detection parameters.

Notifications provided by information systems include, for example, electronic alerts to system administrators.'
  desc 'check', 'Review container platform runtime documentation and configuration settings. 

If the container platform is not configured to notify organization-defined information system role when anomalies in the operation of security functions as defined by site security plan are discovered, this is a finding.'
  desc 'fix', 'Configure the container platform runtime to notify system administrator and operation staff when anomalies in the operation of the security functions as defined in site security plan are discovered.'
  impact 0.5
  ref 'DPMS Target Container Platform'
  tag check_id: 'C-36180r601878_chk'
  tag severity: 'medium'
  tag gid: 'V-233244'
  tag rid: 'SV-233244r601879_rule'
  tag stig_id: 'SRG-APP-000474-CTR-001180'
  tag gtitle: 'SRG-APP-000474'
  tag fix_id: 'F-36148r601220_fix'
  tag 'documentable'
  tag cci: ['CCI-002702']
  tag nist: ['SI-6 d']
end
