control 'SV-95149' do
  title 'The Bromium Enterprise Controller (BEC) must be configured so that organization-identified administrator roles have permission to change, based on selectable criteria, the types of Bromium vSentry client events that are captured in the events log and stored in the SQL database with immediate effect.'
  desc 'If authorized individuals do not have the ability to modify auditing parameters in response to a changing threat environment, the organization may not be able to respond effectively and important forensic information may be lost.

This requirement enables organizations to extend or limit auditing as necessary to meet organizational requirements. Auditing that is limited to conserve information system resources may be extended to address certain threat situations. In addition, auditing may be limited to a specific set of events to facilitate audit reduction, analysis, and reporting. Organizations can establish time thresholds in which audit actions are changed (for example, near real-time, within minutes, or within hours).

DoD requires that privileges be assigned to roles and groups rather than individual user accounts.

The BEC audit log ("history.log") is configured by default to capture all administrator activity. This cannot be disabled.

Roles/Groups:
Users are assigned to groups, and groups are assigned to roles. Roles can be customized to include or disable all admin privileges on the Controller. The Administrator role is configured by default; additional roles can be customized and defined by the site.

The event log setting within the endpoint policy editor is selectable via list. Filtering log events is recommended via the event server (e.g., SIEM or syslog).

Any modifications to the event criteria take effect immediately upon change. 

A default policy must be created for each BEC. DoD requires the Logging level in the default policy to be set to "Event" at a minimum unless there are overriding operational and incident requirements.'
  desc 'check', %q(Review each role and verify that at least one role has the "Edit Policies" privilege. Also verify that not all roles have the "Edit Policies" permission.

1. Using the management console, navigate to "Settings" and click on "Roles".
2. Inspect each role to ensure that the "Edit Policies" permission is enabled/disabled for the appropriate roles (e.g., the site's read-only role must not have permission to edit policies).

Inspect the default policy to ensure that the proper log level has been selected.

1. Select the site's default policy.
2. Navigate to the "Manageability" tab. 
3. Verify "Events" log level is selected.

If the BEC is not configured for organization-identified roles that have permission to change, based on selectable criteria, the types of endpoint events that are captured in the Event log and stored in the SQL database, this is a finding.)
  desc 'fix', %q(The logging level is changed by selecting the "Manageability" level. Groups/roles that have permission to edit policies are allowed to change log event criteria.

1. Using the management console, navigate to "Policies".
2. Select the site's default policy.
3. Navigate to the "Manageability" tab.
4. Select the desired logging level. The default setting is "Event" (e.g., Debug, Trace, Event, Warning). DoD requires a setting of "Event" in the default policy.
5. Click "Save and Deploy".)
  impact 0.3
  ref 'DPMS Target Bromium Secure Platform'
  tag check_id: 'C-80117r1_chk'
  tag severity: 'low'
  tag gid: 'V-80445'
  tag rid: 'SV-95149r1_rule'
  tag stig_id: 'BROM-00-000740'
  tag gtitle: 'SRG-APP-000353'
  tag fix_id: 'F-87251r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001914']
  tag nist: ['AU-12 (3)']
end
