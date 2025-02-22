control 'SRG-OS-000342-CLD-000020_rule' do
  title 'The IaaS/PaaS must perform centralized logging to capture and store log records.'
  desc 'Protection of log data includes assuring log data is not accidentally lost or deleted. Backing up audit records to a different system or onto separate media than the system being audited on an organizationally defined frequency helps to assure in the event of a catastrophic system failure, the audit records will be retained. 

This helps to ensure a compromise of the information system being audited does not also result in a compromise of the audit records.

For cloud service environments, the SIEM or syslog capability must be implemented by both Boundary and Mission CND service providers to log audit information. Services such as SCCA also help with aggregation and normalizing capabilities.

This requirement can be met by the operating system continuously sending records to a centralized logging server.'
  desc 'check', 'If this is an SaaS implementation, this is not a finding.

Verify the IaaS/PaaS is configured to use centralized logging and SIEM server to capture and store the log records produced by the VM management on the IaaS/PaaS.

If IaaS/PaaS does not perform centralized logging and SIEM services to capture and store the log records produced by the VM management, this is a finding.'
  desc 'fix', 'This applies to all Impact Levels.
FedRAMP - Does not match DOD requirement explicitly. Allows up to seven days for offloading. Moderate, High

Implement a solution for centralized logging and SIEM services to capture and store the log records produced on the IaaS/PaaS.'
  impact 0.5
  tag check_id: 'C-SRG-OS-000342-CLD-000020_chk'
  tag severity: 'medium'
  tag gid: 'SRG-OS-000342-CLD-000020'
  tag rid: 'SRG-OS-000342-CLD-000020_rule'
  tag stig_id: 'SRG-OS-000342-CLD-000020'
  tag gtitle: 'SRG-OS-000342-CLD-000020'
  tag fix_id: 'F-SRG-OS-000342-CLD-000020_fix'
  tag 'documentable'
  tag cci: ['CCI-001575', 'CCI-001851']
  tag nist: ['AU-9 (2)', 'AU-4 (1)']
end
