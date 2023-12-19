control 'SV-222478' do
  title 'The application must generate audit records containing the full-text recording of privileged commands or the individual identities of group account users.'
  desc 'Reconstruction of harmful events or forensic analysis is not possible if audit records do not contain enough information.

Organizations consider limiting the additional audit information to only that information explicitly needed for specific audit requirements. The additional information required is dependent on the type of information (i.e., sensitivity of the data and the environment within which it resides). At a minimum, the organization must audit either full-text recording of privileged commands or the individual identities of group users, or both. The organization must maintain audit trails in sufficient detail to reconstruct events to determine the cause and impact of compromise. 

In addition, the application must have the capability to include organization-defined additional, more detailed information in the audit records for audit events.'
  desc 'check', 'Review application documentation and interview application administrator. Identify audit log locations and review audit logs.

Access the system as a privileged user and execute privileged commands.

Review the application logs and ensure that the logs contain all details of the actions performed.  

If a privileged command was typed within the application that command text must be included in the logs. Authentication information provided as part of the text must NOT be logged, just the commands.

If an action was performed, such as activating a check box, that action must be logged.

Review group account users, review logs to determine if the individual users of group accounts are identified in the logs.

If the application does not log the full text recording of privileged commands or if the application does not identify and log the individuals associated with group accounts, this is a finding.'
  desc 'fix', 'Configure the application to log the full text recording of privileged commands or the individual identities of group users.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24148r493342_chk'
  tag severity: 'medium'
  tag gid: 'V-222478'
  tag rid: 'SV-222478r879569_rule'
  tag stig_id: 'APSC-DV-001030'
  tag gtitle: 'SRG-APP-000101'
  tag fix_id: 'F-24137r493343_fix'
  tag 'documentable'
  tag legacy: ['V-69439', 'SV-84061']
  tag cci: ['CCI-000135']
  tag nist: ['AU-3 (1)']
end
