control 'SV-254097' do
  title 'Nutanix AOS must automatically terminate a user session after 15 minutes of inactivity.'
  desc "An attacker can take advantage of user sessions that are left open, thus bypassing the user authentication process.

To thwart the vulnerability of open and unused user sessions, the application server must be configured to close the sessions when a configured condition or trigger event is met.

Session termination terminates all processes associated with a user's logical session except those processes specifically created by the user (i.e., session owner) to continue after the session is terminated.

Conditions or trigger events requiring automatic session termination can include, for example, periods of user inactivity, targeted responses to certain types of incidents, and time-of-day restrictions on information system use.

"
  desc 'check', 'Confirm Nutanix AOS Session Timeout settings are set to 15 minutes.

1. Log in to Prism Element.
2. Click on the gear icon in the upper right.
3. Navigate to "UI Settings" in the left navigation pane.

For each user type, verify that the Session Timeout is set correctly. If not, this is a finding.'
  desc 'fix', 'Configure Nutanix AOS Session Timeout settings to 15 minutes.

1. Log in to Prism Element.
2. Click on the gear icon in the upper right.
3. Navigate to "UI Settings" in the left navigation pane. 
4. Set the Session Timeout settings to 15 minutes per user type.'
  impact 0.5
  ref 'DPMS Target Nutanix AOS 5.20.x Application'
  tag check_id: 'C-57582r846377_chk'
  tag severity: 'medium'
  tag gid: 'V-254097'
  tag rid: 'SV-254097r846379_rule'
  tag stig_id: 'NUTX-AP-000010'
  tag gtitle: 'SRG-APP-000295-AS-000263'
  tag fix_id: 'F-57533r846378_fix'
  tag satisfies: ['SRG-APP-000295-AS-000263', 'SRG-APP-000389-AS-000253', 'SRG-APP-000390-AS-000254']
  tag 'documentable'
  tag cci: ['CCI-002038', 'CCI-002039', 'CCI-002361']
  tag nist: ['IA-11', 'IA-11', 'AC-12']
end
