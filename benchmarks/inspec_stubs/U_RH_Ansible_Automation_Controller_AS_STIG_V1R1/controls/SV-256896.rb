control 'SV-256896' do
  title 'Automation Controller must limit the number of concurrent sessions to an organization-defined number for all accounts and/or account types.'
  desc 'Application management includes the ability to control the number of sessions that utilize an application by all accounts and/or account types. Limiting the number of allowed sessions is helpful in limiting risks related to denial-of-service attacks.

Automation Controllers host and expose business logic and application processes.

Automation Controller limits the maximum number of concurrent sessions in a manner that affects the entire application server or on an individual application basis.

The settings must follow DOD-recommended values, but the settings should be configurable to allow for future DOD direction.

While the DOD will specify recommended values, the values can be adjusted to accommodate the operational requirement of a given system.

'
  desc 'check', 'As a System Administrator for each Automation Controller host, navigate to the Automation Controller web administrator console:
Settings >> System >> Miscellaneous Authentication settings.

Verify the "Maximum Number of simultaneous logged in sessions" field is set according to policy.

If this configuration setting does not match the organizationally defined maximum, or is set to -1 (negative one), this is a finding.'
  desc 'fix', 'As a System Administrator for each Automation Controller host, navigate to the Automation Controller web administrator console:
Settings >> System >> Miscellaneous Authentication settings.

Click "Edit".

Change "Maximum Number of simultaneous logged in sessions" to match the organizationally defined maximum or greater than 0.

Click "Save".'
  impact 0.5
  ref 'DPMS Target Red Hat Ansible Automation Controller App Server'
  tag check_id: 'C-60571r903542_chk'
  tag severity: 'medium'
  tag gid: 'V-256896'
  tag rid: 'SV-256896r903543_rule'
  tag stig_id: 'APAS-AT-000010'
  tag gtitle: 'SRG-APP-000001-AS-000001'
  tag fix_id: 'F-60513r903543_fix'
  tag satisfies: ['SRG-APP-000001-AS-000001', 'SRG-APP-000295-AS-000263']
  tag 'documentable'
  tag cci: ['CCI-000054', 'CCI-002361']
  tag nist: ['AC-10', 'AC-12']
end
