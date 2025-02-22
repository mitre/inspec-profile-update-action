control 'SV-233242' do
  title 'The organization-defined role must verify correct operation of security functions in the container platform.'
  desc 'Without verification, security functions may not operate correctly and this failure may go unnoticed within the container platform. The container platform components must identity and ensure the security functions are still operational and applicable to the organization.

Security functions are responsible for enforcing the system security policy and supporting the isolation of code and data on which the protection is based. Security functionality includes, but is not limited to, establishing system accounts, configuring access authorizations (i.e., permissions, privileges), setting events to be audited, and setting intrusion detection parameters.

Notifications provided by information systems include, for example, electronic alerts to system administrators.'
  desc 'check', 'Review container platform documentation and configuration verification of the correct operation of security functions, which may include the valid connection to an external security manager (ESM). 

If verification of the correct operation of security functions is not performed, this is a finding.'
  desc 'fix', 'Configure the container platform configuration and installation settings to perform verification of the correct operation of security functions.'
  impact 0.5
  ref 'DPMS Target Container Platform'
  tag check_id: 'C-36178r601831_chk'
  tag severity: 'medium'
  tag gid: 'V-233242'
  tag rid: 'SV-233242r601832_rule'
  tag stig_id: 'SRG-APP-000472-CTR-001170'
  tag gtitle: 'SRG-APP-000472'
  tag fix_id: 'F-36146r601214_fix'
  tag 'documentable'
  tag cci: ['CCI-002696']
  tag nist: ['SI-6 a']
end
