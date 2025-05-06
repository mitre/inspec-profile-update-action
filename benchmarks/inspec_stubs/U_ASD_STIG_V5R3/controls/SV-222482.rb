control 'SV-222482' do
  title 'The application must be configured to write application logs to a centralized log repository.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration.  In addition, attackers often manipulate logs to hide or obfuscate their activity.

Off-loading is a common process in information systems with limited audit storage capacity or when trying to assure log availability and integrity.

This requirement is meant to address space limitations and integrity issues that can be encountered when storing logs on the local server.

The goal of the requirement being to offload application logs to a separate server as quickly and efficiently as possible so as to mitigate these risks.'
  desc 'check', 'Review application documentation and interview application administrator.

Evaluate application log management processes and determine if the system is configured to utilize a centralized log management system for the hosting and management of application audit logs.

If the system is not configured to write the application logs to the centralized log management repository in an expeditious manner, this is a finding.'
  desc 'fix', 'Configure the application to utilize a centralized log repository and ensure the logs are off-loaded from the application system as quickly as possible.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24152r493354_chk'
  tag severity: 'medium'
  tag gid: 'V-222482'
  tag rid: 'SV-222482r879886_rule'
  tag stig_id: 'APSC-DV-001080'
  tag gtitle: 'SRG-APP-000515'
  tag fix_id: 'F-24141r493355_fix'
  tag 'documentable'
  tag legacy: ['SV-84069', 'V-69447']
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
