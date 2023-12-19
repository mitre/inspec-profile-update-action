control 'SV-233169' do
  title 'Audit records must be stored at a secondary location.'
  desc 'Auditable events are used in the investigation of incidents and must be protected from being deleted or altered. Often, events that took place in the past must be viewed to understand the entire incident. For the purposes of audit event protection and recall, audit events are often off-loaded to an external storage location. The container platform must provide a mechanism to assist in the off-loading of the audit data or at a minimum, must not hinder an external process used for audit event off-loading.'
  desc 'check', 'Verify the log records are being off-loaded to a separate system or transferred from the container platform storage location to a storage location other than the container platform itself. 

The information system may demonstrate this capability using a log management application, system configuration, or other means. 

If logs are not being off-loaded, this is a finding.'
  desc 'fix', 'Configure the container platform to off-load the logs to a remote log or management server.'
  impact 0.5
  ref 'DPMS Target Container Platform'
  tag check_id: 'C-36105r601783_chk'
  tag severity: 'medium'
  tag gid: 'V-233169'
  tag rid: 'SV-233169r879731_rule'
  tag stig_id: 'SRG-APP-000358-CTR-000805'
  tag gtitle: 'SRG-APP-000358'
  tag fix_id: 'F-36073r600995_fix'
  tag 'documentable'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
