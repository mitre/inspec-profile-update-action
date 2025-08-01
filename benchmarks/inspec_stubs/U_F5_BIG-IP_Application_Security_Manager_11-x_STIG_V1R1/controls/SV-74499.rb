control 'SV-74499' do
  title 'The BIG-IP ASM module must be configured to produce ASM Event Logs containing information to establish what type of unauthorized events occurred.'
  desc 'Without establishing what type of event occurred, it would be difficult to establish, correlate, and investigate the events leading up to an outage or attack.

Event log content that may be necessary to satisfy this requirement includes, for example, event descriptions, success/fail indications, filenames involved, and access control or flow control rules invoked.

Associating event types with detected events in the event logs provide a means of investigating an attack, recognizing resource utilization or capacity thresholds, or identifying an improperly configured network element.

This requirement does not apply to audit logs generated on behalf of the device itself (management).'
  desc 'check', 'Verify the BIG-IP ASM module is configured to produce ASM Event Logs containing information to establish what type of unauthorized events occurred.

Navigate to the BIG-IP System manager >> Local Traffic >> Virtual Servers >> Virtual Servers List tab.

Select Virtual Servers(s) from the list to verify the configuration for ASM Event Logging.

Navigate to the Security >> Policies tab.

Set "Policy Settings" to "Advanced".

Verify that "Application Security Policy" is Enabled and "Policy" is set to use an ASM policy for the virtual server.

Verify that "Log Profile" is Enabled and a logging profile is assigned under "Selected".

Navigate to the BIG-IP System manager >> Security >> Event Logs >> Logging Profiles.

Select the Logging Profile that was assigned to the virtual server.

Verify "Request Type" is set to "Illegal requests, and requests that include staged attack signatures" is selected under "Storage Filter".

If the BIG-IP ASM module does not produce ASM Event Logs containing information to establish what type of unauthorized events occurred, this is a finding.'
  desc 'fix', %q(Configure the BIG-IP ASM module to produce ASM Event Logs containing information to establish what type of unauthorized events occurred. 

Navigate to the BIG-IP System manager >> Security >> Event Logs >> Logging Profiles.

Click on 'Create'.

Name the Profile.

Check the box next to 'Application Security'.

Set "Request Type" to "Illegal requests, and requests that include staged attack signatures" under "Storage Filter".

Click 'Finished'.

Apply Logging Profile to applicable Virtual Server(s).

Navigate to the BIG-IP System manager >> Local Traffic >> Virtual Servers >> Virtual Servers List tab.

Select Virtual Servers(s) from the list to assign the ASM Event Logging Profile.

Navigate to the Security >> Policies tab.

Set "Policy Settings" to "Advanced".

Verify that "Application Security Policy" is Enabled and "Policy" is set to use an ASM policy for the virtual server.

Under "Log Profile" set to Enabled and move new Logging Profile from "Available" to "Selected".

Click "Update".)
  impact 0.5
  ref 'DPMS Target F5 BIG-IP ASM 11.x'
  tag check_id: 'C-60749r1_chk'
  tag severity: 'medium'
  tag gid: 'V-60069'
  tag rid: 'SV-74499r1_rule'
  tag stig_id: 'F5BI-AS-000039'
  tag gtitle: 'SRG-NET-000074-ALG-000043'
  tag fix_id: 'F-65479r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000130']
  tag nist: ['AU-3 a']
end
