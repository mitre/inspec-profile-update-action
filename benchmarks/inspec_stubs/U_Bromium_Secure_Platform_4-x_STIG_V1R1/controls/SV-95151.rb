control 'SV-95151' do
  title 'The Bromium Enterprise Controller (BEC) must be configured to permit only authorized users to remotely view, in real time (within seconds of event occurring), all content related to an established Bromium vSentry client session.'
  desc 'Without the capability to remotely view/hear all content related to a user session, investigations into suspicious user activity would be hampered. Real-time monitoring allows authorized personnel to take action before additional damage is done. The ability to observe user sessions as they are happening allows for interceding in ongoing events that after-the-fact review of captured content would not allow.

The Bromium monitoring module can capture end-user activity related to applications, processes, files, registry activity, and file activity. Custom rules can also be created to report on desired activity and conditions. Event data is sent back to the BEC without having to access the endpoint.'
  desc 'check', 'Ask the site representative for a list of administrators who are authorized to view Bromium vSentry client activity. Verify unauthorized users are not members of groups that have been assigned roles that have the "View Events" and "View Threats" privilege.

1. From the BEC console, navigate to "Settings".
2. Select "Roles". 
3. Click on each Role to see which ones have "View Events" and "View Threats" checked.
4. For the Roles which have enabled for "View Events" or "View Threats", navigate to the Groups area and check which Groups they are assigned to.
5. Navigate to "Settings" and "User Groups" to verify that users who are not on the list are not assigned to Groups with Roles that have "View Events" or "View Threats" enabled.

If the BEC is not configured to permit only authorized users to remotely view, in real time (within seconds of event occurring), all content related to an established Bromium vSentry client session, this is a finding.'
  desc 'fix', 'The administrator must be in a group that has a role with permissions to view Events and Threats. To give an administrator permission to view Event and Threat configured us the following threat.

1. Using the management console, navigate to "Settings".
2. Select "Roles".
3. Select the role(s) that need permission to view user sessions and activity.
4. Under the "Events" section, enable the "View Events" permission.
5. Under the "Threats" section, enable the "View Threats" permission. 
6. Click "Save Changes".'
  impact 0.3
  ref 'DPMS Target Bromium Secure Platform'
  tag check_id: 'C-80119r1_chk'
  tag severity: 'low'
  tag gid: 'V-80447'
  tag rid: 'SV-95151r1_rule'
  tag stig_id: 'BROM-00-000755'
  tag gtitle: 'SRG-APP-000355'
  tag fix_id: 'F-87253r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001920']
  tag nist: ['AU-14 (3)']
end
