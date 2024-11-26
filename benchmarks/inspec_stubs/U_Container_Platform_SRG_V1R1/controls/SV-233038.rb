control 'SV-233038' do
  title 'The container platform must generate audit records for all DoD-defined auditable events within all components in the platform.'
  desc 'Within the container platform, audit data can be generated from any of the deployed container platform components. This audit data is important when there are issues, including security incidents that must be investigated. To make the audit data worthwhile for the investigation of events, it is necessary to have the appropriate and required data logged. To handle the need to log DoD-defined auditable events, the container platform must offer a mechanism to change and manage the events that are audited.'
  desc 'check', 'Review the container platform configuration to determine if the container platform is configured to generate audit records for all DoD-defined auditable events within all components in the platform. 

Generate DoD-defined auditable events within all the components to determine if the events are being audited. 

If the container platform is not configured to generate audit records for all DoD-defined auditable events within the components or the events are  not generating audit records, this is a finding.'
  desc 'fix', 'Configure the container platform to generate audit records for all DoD-defined auditable events within all the components of the container platform.'
  impact 0.5
  ref 'DPMS Target Container Platform'
  tag check_id: 'C-35974r599520_chk'
  tag severity: 'medium'
  tag gid: 'V-233038'
  tag rid: 'SV-233038r599521_rule'
  tag stig_id: 'SRG-APP-000089-CTR-000150'
  tag gtitle: 'SRG-APP-000089'
  tag fix_id: 'F-35942r598751_fix'
  tag 'documentable'
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
