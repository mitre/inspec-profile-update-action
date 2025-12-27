control 'SV-220407' do
  title 'MarkLogic Server must generate audit records when unsuccessful attempts to delete categories of information (e.g., classification levels/security levels) occur.'
  desc 'Changes in categories of information must be tracked. Without an audit trail, unauthorized access to protected data could go undetected.

To aid in diagnosis, it is necessary to keep track of failed attempts in addition to the successful ones.

For detailed information on categorizing information, refer to FIPS Publication 199, Standards for Security Categorization of Federal Information and Information Systems, and FIPS Publication 200, Minimum Security Requirements for Federal Information and Information Systems.'
  desc 'check', 'Check MarkLogic audit configurations to verify that audit records are produced when the system denies attempts, or when other errors prevent attempts to delete categories of information.

Perform the check from the MarkLogic Server Admin Interface with a user that holds administrative-level privileges.

1. Click the Groups icon.
2. Click the group in which the configuration to be checked resides (e.g., Default).
3. Click the Auditing icon on the left tree menu.
4. Inspect the audit enabled field. A value of false means auditing is not enabled and this is a finding. 
5. If audit enabled field is true, but the document-update event is not selected, this is a finding.
6. Under the Audit Restrictions - Outcome section, verify the security-access event for auditing is set to "both". If the setting is not both, this is a finding.
7. If any roles, URIs, or users are identified in audit restrictions and not documented in the System Security Plan, this is a finding.'
  desc 'fix', 'Perform the fix from the MarkLogic Server Admin Interface with a user that holds administrative-level privileges.

1. Click the Groups icon.
2. Click the group in which the configuration to be checked resides (e.g., Default).
3. Click the Auditing icon on the left tree menu.
4. Set the audit enabled field to true.
5. Enable the document-update event for auditing.
6. Enable "both" for the audit restriction under the outcome selection.
7. Ensure no roles, URIs, or users are identified in the audit restrictions, unless documented in the System Security Plan. 

See MarkLogic Server - Using Security Guide 9.0-9, Ch 5, Section 2: Configuring Compartment Security, for information on defining the categories of information by using compartmented security.'
  impact 0.5
  ref 'DPMS Target MarkLogic Server v9'
  tag check_id: 'C-22122r401672_chk'
  tag severity: 'medium'
  tag gid: 'V-220407'
  tag rid: 'SV-220407r622777_rule'
  tag stig_id: 'ML09-00-011000'
  tag gtitle: 'SRG-APP-000502-DB-000349'
  tag fix_id: 'F-22111r401673_fix'
  tag 'documentable'
  tag legacy: ['SV-110163', 'V-101059']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
