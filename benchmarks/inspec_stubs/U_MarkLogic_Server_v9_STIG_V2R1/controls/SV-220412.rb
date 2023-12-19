control 'SV-220412' do
  title 'MarkLogic Server must generate audit records when concurrent logons/connections by the same user from different workstations occur.'
  desc 'For completeness of forensic analysis, it is necessary to track who logs on to the DBMS.

Concurrent connections by the same user from multiple workstations may be valid uses of the system, such connections may be due to improper circumvention of the requirement to use the CAC for authentication, may indicate unauthorized account sharing, or may be because an account has been compromised.

(If the fact of multiple, concurrent logons by a given user can be reliably reconstructed from the log entries for other events (logons/connections; voluntary and involuntary disconnections), then it is not mandatory to create additional log entries specifically for this.)'
  desc 'check', 'Check MarkLogic audit configuration to verify whether audit records are generated each time a user (or other principal) who is already connected to the DBMS logs on or connects to the DBMS from a different workstation.

Perform the check from the MarkLogic Server Admin Interface with a user that holds administrative-level privileges.

1. Click the Groups icon.
2. Click the group in which the configuration to be checked resides (e.g., Default).
3. Click the Auditing icon on the left tree menu.
4. Inspect the audit enabled field. A value of false means auditing is not enabled and this is a finding. 
5. If audit enabled field is true, but the security-access event is not selected, this is a finding.
6. Under the Audit Restrictions - Outcome section, verify the security-access event for auditing is set to "both". If the setting is not "both", this is a finding.
7. If any roles, URIs, or users are identified in audit restrictions and not documented in the System Security Plan, this is a finding.'
  desc 'fix', 'Configure MarkLogic audit settings to generate an audit record each time a user (or other principal) who is already connected to the DBMS logs on or connects to the DBMS from a different workstation.

Perform the fix from the MarkLogic Server Admin Interface with a user that holds administrative-level privileges.

1. Click the Groups icon.
2. Click the group in which the configuration to be checked resides (e.g., Default).
3. Click the Auditing icon on the left tree menu.
4. Set the audit enabled field to true.
5. Enable the security-access and concurrent-request-denial events for auditing.
6. Enable "both" for the audit restriction under the outcome selection.
7. Ensure no roles, URIs, or users are identified in the audit restrictions, unless documented in the System Security Plan.'
  impact 0.5
  ref 'DPMS Target MarkLogic Server v9'
  tag check_id: 'C-22127r401687_chk'
  tag severity: 'medium'
  tag gid: 'V-220412'
  tag rid: 'SV-220412r622777_rule'
  tag stig_id: 'ML09-00-011600'
  tag gtitle: 'SRG-APP-000506-DB-000353'
  tag fix_id: 'F-22116r401688_fix'
  tag 'documentable'
  tag legacy: ['SV-110173', 'V-101069']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
