control 'SV-228999' do
  title 'The BIG-IP appliance must be configured to automatically terminate a network administrator session after organization-defined conditions or trigger events requiring session disconnect.'
  desc "Automatic session termination addresses the termination of administrator-initiated logical sessions in contrast to the termination of network connections that are associated with communications sessions (i.e., network disconnect). A logical session (for local, network, and remote access) is initiated whenever an administrator (or process acting on behalf of a user) accesses a network device. Such administrator sessions can be terminated (and thus terminate network administrator access) without terminating network sessions. 

Session termination terminates all processes associated with an administrator's logical session except those processes that are specifically created by the administrator (i.e., session owner) to continue after the session is terminated. 

Conditions or trigger events requiring automatic session termination can include, for example, organization-defined periods of user inactivity, targeted responses to certain types of incidents, and time-of-day restrictions on information system use. These conditions will vary across environments and network device types."
  desc 'check', 'Verify the BIG-IP appliance is configured to automatically terminate an administrator session after organization-defined conditions or trigger events requiring session disconnect. 

Navigate to the BIG-IP System manager >> System >> Preferences.

Review the "Security Settings" section.

Verify "Idle Time Before Automatic Logout" is set to 900 seconds or less.

Verify "Restrict A Consistent Inbound IP For The Entire Session" is Enabled.

Verify "Enforce Idle Timeout While View Dashboard" is Enabled.

If the BIG-IP appliance is not configured to automatically terminate an administrator session under the designated conditions or trigger events, this is a finding.'
  desc 'fix', 'Configure the BIG-IP appliance to automatically terminate an administrator session after organization-defined conditions or trigger events requiring session disconnect.'
  impact 0.7
  ref 'DPMS Target F5 BIG-IP Device Management 11.x'
  tag check_id: 'C-31314r518042_chk'
  tag severity: 'high'
  tag gid: 'V-228999'
  tag rid: 'SV-228999r557520_rule'
  tag stig_id: 'F5BI-DM-000163'
  tag gtitle: 'SRG-APP-000516-NDM-000317'
  tag fix_id: 'F-31291r518043_fix'
  tag 'documentable'
  tag legacy: ['V-60185', 'SV-74615']
  tag cci: ['CCI-000366', 'CCI-002361']
  tag nist: ['CM-6 b', 'AC-12']
end
