control 'SV-220342' do
  title 'MarkLogic Server must protect against a user falsely repudiating having performed organization-defined actions.'
  desc "Non-repudiation of actions taken is required in order to maintain data integrity. Examples of particular actions taken by individuals include creating information, sending a message, approving information (e.g., indicating concurrence or signing a contract), and receiving a message. 

Non-repudiation protects against later claims by a user of not having created, modified, or deleted a particular data item or collection of data in the database.

In designing a database, the organization must define the types of data and the user actions that must be protected from repudiation. The implementation must then include building audit features into the application data tables and configuring the DBMS's audit tools to capture the necessary audit trail. Design and implementation also must ensure that applications pass individual user identification to the DBMS, even where the application connects to the DBMS with a standard, shared account.

MarkLogic Server includes an auditing capability. Auditing can be enabled to capture security-relevant events to monitor suspicious database activity or to satisfy applicable auditing requirements. Configure the generation of audit events by including or excluding MarkLogic Server roles, users, or documents based on URI. 

More information on auditing can be found here:
https://docs.marklogic.com/guide/security/auditing"
  desc 'check', 'Review the configuration of audit logs to determine whether auditing includes details identifying the individual user. If it does not, this is a finding.

Perform the check from the MarkLogic Server Admin Interface with a user that holds administrative-level privileges.

1. Click the Groups icon.
2. Click the group in which the configuration to check resides (e.g., Default).
3. Click the Auditing icon on the left tree menu.
4. Inspect the audit-enabled field. A value of false means there is no auditing identifying the individual user and this is a finding. 
5. If audit enabled field is true, but the settings do not meet the DoD minimum requirements for non-repudiation, this is a finding.'
  desc 'fix', 'Configure MarkLogic audit logs to ensure auditing includes details identifying the individual user.

Perform the fix from the MarkLogic Server Admin Interface with a user that holds administrative-level privileges.

1. Click the Groups icon.
2. Click the group in which the configuration to check resides (e.g., Default).
3. Click the Auditing icon on the left tree menu.
4. Set the audit enabled field to true.
5. Configure the settings to meet DoD minimum requirements for protection against a user falsely repudiating.'
  impact 0.5
  ref 'DPMS Target MarkLogic Server v9'
  tag check_id: 'C-22057r531248_chk'
  tag severity: 'medium'
  tag gid: 'V-220342'
  tag rid: 'SV-220342r622777_rule'
  tag stig_id: 'ML09-00-000400'
  tag gtitle: 'SRG-APP-000080-DB-000063'
  tag fix_id: 'F-22046r401478_fix'
  tag 'documentable'
  tag legacy: ['SV-110031', 'V-100927']
  tag cci: ['CCI-000166']
  tag nist: ['AU-10']
end
