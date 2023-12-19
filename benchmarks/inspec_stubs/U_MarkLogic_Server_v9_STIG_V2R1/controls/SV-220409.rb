control 'SV-220409' do
  title 'MarkLogic Server must generate audit records when unsuccessful logons or connection attempts occur.'
  desc 'For completeness of forensic analysis, it is necessary to track failed attempts to log on to the DBMS. While positive identification may not be possible in a case of failed authentication, as much information as possible about the incident must be captured.'
  desc 'check', 'Check MarkLogic audit settings to verify an audit record is generated each time a user (or other principal) attempts but fails to log on or connect to the DBMS (including attempts where the user ID is invalid/unknown).

Perform the check from the MarkLogic Server Admin Interface with a user that holds administrative-level privileges.

1. Click the Groups icon.
2. Click the group in which the configuration to be checked resides e.g., Default).
3. Click the Auditing icon on the left tree menu.
4. Inspect the audit enabled field. A value of false means auditing is not enable and this is a finding. 
5. If audit enabled field is true but the authentication-failure event is not selected, this is a finding.
6. Under the Audit Restrictions - Outcome section, verify the security-access event for auditing is set to "both". If the setting is not "both", this is a finding.
7. If any roles, URIs, or users are identified in audit restrictions and not documented in the System Security Plan, this is a finding.'
  desc 'fix', 'Configure MarkLogic audit settings to generate an audit record each time a user (or other principal) attempts but fails to log on or connect to the DBMS (including attempts where the user ID is invalid/unknown).

Include attempts where the user ID is invalid/unknown. Ensure that the audit record contains the time of the event and the user ID that was entered (if any).

Perform the fix from the MarkLogic Server Admin Interface with a user that holds administrative-level privileges.

1. Click the Groups icon.
2. Click the group in which the configuration to be checked resides (e.g., Default).
3. Click the Auditing icon on the left tree menu.
4. Set the audit enabled field to true.
5. Enable the authentication-failure event for auditing.
6. Enable "both" for the audit restriction under the outcome selection.
7. Ensure no roles, URIs or users are identified in the audit restrictions, unless documented in the System Security Plan.'
  impact 0.5
  ref 'DPMS Target MarkLogic Server v9'
  tag check_id: 'C-22124r401678_chk'
  tag severity: 'medium'
  tag gid: 'V-220409'
  tag rid: 'SV-220409r622777_rule'
  tag stig_id: 'ML09-00-011200'
  tag gtitle: 'SRG-APP-000503-DB-000351'
  tag fix_id: 'F-22113r401679_fix'
  tag 'documentable'
  tag legacy: ['SV-110167', 'V-101063']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
