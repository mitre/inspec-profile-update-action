control 'SV-95167' do
  title 'The Bromium Enterprise Controller (BEC) Update Interval must be set to a maximum of one hour.'
  desc "Without reauthenticating the endpoint, unidentified or unknown devices may be introduced, thereby facilitating malicious activity.

The BEC Update Interval setting controls the frequency of check-ins for policy updates, remote commands and a Bromium vSentry event data. The value set is in seconds. During the update connection with the BEC, the Bromium vSentry client's device certificate is reauthenticated."
  desc 'check', 'Verify the Update Interval is set to one hour.

1. From the management console, navigate to the "Policies" menu.
2. Select the Base policy.
3. Click the "Manageability" tab.
4. Inspect the "Update Interval" parameter to reflect the desired interval (1 hour/3600 seconds is the maximum).

If the BEC Update Interval is set to more than one hour, this is a finding.'
  desc 'fix', 'Configure the Update Internal for the BEC/vSentry client update of event data, remote commands, policy updates, and reauthenication.

1. From the management console, navigate to the "Policies" menu.
2. Select the Base policy.
3. Click the "Manageability" tab. 
4. Edit the "Update Interval" parameter to reflect "3600" seconds. 
5. Click "Save and Deploy".

Note: A value of 1 hour/3600 seconds is the recommended setting; however, the setting may be changed to a lower interval based on mission needs.'
  impact 0.5
  ref 'DPMS Target Bromium Secure Platform'
  tag check_id: 'C-80135r1_chk'
  tag severity: 'medium'
  tag gid: 'V-80463'
  tag rid: 'SV-95167r1_rule'
  tag stig_id: 'BROM-00-000905'
  tag gtitle: 'SRG-APP-000390'
  tag fix_id: 'F-87269r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002039']
  tag nist: ['IA-11']
end
