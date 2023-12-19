control 'SV-80125' do
  title 'The MaaS360 Server must be configured to enable all required audit events: Failure to push a new application on a managed mobile device.'
  desc 'Failure to generate these audit records makes it more difficult to identify or investigate attempted or successful compromises, potentially causing incidents to last longer than necessary.

SFR ID: FAU_GEN.1.1(2) Refinement'
  desc 'check', 'Review the MaaS360 server console and confirm the server is configured to alert for audit event failures on managed mobile devices.

On the MaaS360 Console complete the following Steps:
1. Navigate to Security >> Policies and have system administrator identify which mobile operating system (iOS, etc.) the MDM policy alerts apply to. 
2. Open identified policy and go to device settings >> application compliance.
3. Verify that "Configure required applications" is set to "yes" and that all new applications are listed
4. Repeat for other MOS as required (for example, Windows Phone, etc.)

If the "Configure required applications" is not set to "yes" or all new applications are not on the list, this is a finding.'
  desc 'fix', 'Configure the MAS Server to enable all required audit events:  Failure to push a new application on a managed mobile device.

On the MaaS360 Console complete the following Steps:
1. Navigate to Security >> Policies and select the mobile operating system (iOS, etc.) the MDM policy alerts apply to. 
2. Open identified policy and go to device settings >> application compliance.
3. Set "Configure required applications" is set to "yes" and list all new applications
4. Repeat for other MOS as required (for example, Windows Phone, etc.)'
  impact 0.5
  ref 'DPMS Target IBM MaaS360 v2.3.x MDM'
  tag check_id: 'C-66195r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65635'
  tag rid: 'SV-80125r1_rule'
  tag stig_id: 'M360-01-003800'
  tag gtitle: 'PP-MDM-203106'
  tag fix_id: 'F-71563r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000129', 'CCI-000169', 'CCI-000366', 'CCI-001571']
  tag nist: ['AU-2 a', 'AU-12 a', 'CM-6 b', 'AU-2 a']
end
