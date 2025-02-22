control 'SV-96889' do
  title 'The MaaS360 MDM server must be configured to enable all required audit events (if function is not automatically implemented during MDM/MAS server install): a. Failure to push a new application on a managed mobile device.'
  desc 'Failure to generate these audit records makes it more difficult to identify or investigate attempted or successful compromises, potentially causing incidents to last longer than necessary.

SFR ID: FMT_SMF.1.1(3) c,
FAU_GEN.1.1(2)'
  desc 'check', 'Review the MaaS360 server console and confirm the server is configured to alert for audit event failures on managed mobile devices.

On the MaaS360 Console, complete the following steps:
1. Navigate to Security >> Policies and have the System Administrator identify which mobile operating system (iOS, etc.) the MDM policy alerts apply to. 
2. Open the identified policy and go to device settings >> application compliance.
3. Verify that "Configure required applications" is set to "yes" and that all new applications are listed.
4. Repeat for other MOS as required (for example, Android).

If the "Configure required applications" is not set to "yes" or all new applications are not on the list, this is a finding.'
  desc 'fix', 'Configure the MaaS360 server to enable all required audit events: Failure to push a new application on a managed mobile device.

On the MaaS360 Console, complete the following steps:
1. Navigate to Security >> Policies and select the mobile operating system (iOS, etc.) the MDM policy alerts apply to. 
2. Open the identified policy and go to device settings >> application compliance.
3. Set "Configure required applications" to "yes" and list all new applications.
4. Repeat for other MOS as required (for example, iOS, Android, etc.).'
  impact 0.3
  ref 'DPMS Target IBM MaaS360 with Watson v10.x MDM'
  tag check_id: 'C-82003r1_chk'
  tag severity: 'low'
  tag gid: 'V-82175'
  tag rid: 'SV-96889r1_rule'
  tag stig_id: 'M360-10-100200'
  tag gtitle: 'PP-MDM-323202'
  tag fix_id: 'F-89033r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000129', 'CCI-000169', 'CCI-000366']
  tag nist: ['AU-2 a', 'AU-12 a', 'CM-6 b']
end
