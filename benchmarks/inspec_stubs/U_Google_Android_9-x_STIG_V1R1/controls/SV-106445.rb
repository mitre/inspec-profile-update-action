control 'SV-106445' do
  title 'The Google Android Pie must be configured to enable audit logging.'
  desc 'Audit logs enable monitoring of security-relevant events and subsequent forensics when breaches occur. To be useful, Administrators must have the ability to view the audit logs.

SFR ID: FMT_SMF_EXT.1.1 #32'
  desc 'check', 'Review documentation on the Google Android device and inspect the configuration on the Google Android device to enable audit logging.

This validation procedure is performed on only on the MDM Administration Console. 

On the MDM console, do the following:

1. Open the restrictions settings.
2. Open user settings.
3. Select "Enable security logging".
4. Select "Enable network logging".

If the MDM console device policy is not set to enable audit logging, this is a finding.'
  desc 'fix', 'Configure the Google Android Pie to enable audit logging.

On the MDM console:

1. Open the restrictions settings.
2. Open user settings.
3. Select "Enable security logging".
4. Select "Enable network logging".'
  impact 0.5
  ref 'DPMS Target Google Android 9.x'
  tag check_id: 'C-96177r1_chk'
  tag severity: 'medium'
  tag gid: 'V-97341'
  tag rid: 'SV-106445r1_rule'
  tag stig_id: 'GOOG-09-005505'
  tag gtitle: 'PP-MDF-302370'
  tag fix_id: 'F-103021r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000370', 'CCI-001851']
  tag nist: ['CM-6 b', 'CM-6 (1)', 'AU-4 (1)']
end
