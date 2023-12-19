control 'SV-220400' do
  title 'MarkLogic Server must generate audit records when categories of information (e.g., classification levels/security levels) are modified.'
  desc 'Changes in categories of information must be tracked. Without an audit trail, unauthorized access to protected data could go undetected.

For detailed information on categorizing information, refer to FIPS Publication 199, Standards for Security Categorization of Federal Information and Information Systems, and FIPS Publication 200, Minimum Security Requirements for Federal Information and Information Systems.'
  desc 'check', 'Check MarkLogic audit configurations to verify that audit records are produced when categories of information are modified.

Perform the check from the MarkLogic Server Admin Interface with a user that holds administrative-level privileges.

1. Click the Groups icon.
2. Click the group in which the configuration to be checked resides (e.g., Default).
3. Click the Auditing icon on the left tree menu.
4. Inspect the audit enabled field, a value of false means auditing is not enabled, this is a finding. 
5. If audit enabled field is true but the document-update event is not selected, this is a finding.
6. Under the Audit Restrictions - Outcome section, verify the security-access event for auditing is set to "both". If the setting is not both, this is a finding.
7. If any roles, URIs, or users are identified in audit restrictions and not documented in the System Security Plan, this is a finding.'
  desc 'fix', 'Configure MarkLogic to produce audit records when categories of information are modified.

Perform the fix from the MarkLogic Server Admin Interface with a user that holds administrative-level privileges.

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
  tag check_id: 'C-22115r401651_chk'
  tag severity: 'medium'
  tag gid: 'V-220400'
  tag rid: 'SV-220400r622777_rule'
  tag stig_id: 'ML09-00-010300'
  tag gtitle: 'SRG-APP-000498-DB-000346'
  tag fix_id: 'F-22104r401652_fix'
  tag 'documentable'
  tag legacy: ['SV-110149', 'V-101045']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
