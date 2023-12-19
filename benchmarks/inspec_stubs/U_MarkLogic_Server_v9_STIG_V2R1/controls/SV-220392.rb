control 'SV-220392' do
  title 'MarkLogic Server must generate audit records when categories of information (e.g., classification levels/security levels) are accessed.'
  desc 'Changes in categories of information must be tracked. Without an audit trail, unauthorized access to protected data could go undetected.

For detailed information on categorizing information, refer to FIPS Publication 199, Standards for Security Categorization of Federal Information and Information Systems, and FIPS Publication 200, Minimum Security Requirements for Federal Information and Information Systems.'
  desc 'check', 'Review the DBMS/database security and audit configurations to verify that audit records are produced when categories of information are accessed, to include reads, creations, modifications, and deletions.

If they are not produced, this is a finding.

Perform the check from the MarkLogic Server Admin Interface with a user that holds administrative-level privileges.

1. Click the Groups icon.
2. Click the group in which the configuration to be checked resides (e.g., Default).
3. Click the Auditing icon on the left tree menu.
4. Inspect the audit enabled field, a value of false means there is no auditing identifying the individual user, this is a finding. 
5. If audit enabled field is true but the document-read event is not selected, this is a finding.
6. Under the Audit Restrictions - Outcome section, verify the security-access event for auditing is set to "both". If the setting is not both, this is a finding.
7. If the role that has been configured for the category of information is not included under the audit restriction roles, this is a finding.'
  desc 'fix', 'Configure MarkLogic to produce audit records when categories of information are accessed, to include reads, creations, modifications, and deletions.

Perform the fix from the MarkLogic Server Admin Interface with a user that holds administrative-level privileges.

1. Click the Groups icon.
2. Click the group in which the configuration to check resides (e.g., Default).
3. Click the Auditing icon on the left tree menu.
4. Set the audit enabled field to true.
5. Enable the document-read event for auditing.
6. Enable "both" for the audit restriction under the outcome selection.
7. Add the role that encompasses the categories of information that need auditing. See MarkLogic Server - Using Security Guide 9.0-9, Ch 5, Section 2: Configuring Compartment Security, for information on defining the categories of information by using compartmented security.'
  impact 0.5
  ref 'DPMS Target MarkLogic Server v9'
  tag check_id: 'C-22107r401627_chk'
  tag severity: 'medium'
  tag gid: 'V-220392'
  tag rid: 'SV-220392r622777_rule'
  tag stig_id: 'ML09-00-009500'
  tag gtitle: 'SRG-APP-000494-DB-000344'
  tag fix_id: 'F-22096r401628_fix'
  tag 'documentable'
  tag legacy: ['SV-110133', 'V-101029']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
