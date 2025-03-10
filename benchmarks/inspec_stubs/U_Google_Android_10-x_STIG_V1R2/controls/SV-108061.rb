control 'SV-108061' do
  title 'Google Android 10 must be configured to enable audit logging.'
  desc 'Audit logs enable monitoring of security-relevant events and subsequent forensics when breaches occur. To be useful, Administrators must have the ability to view the audit logs.

SFR ID: FMT_SMF_EXT.1.1 #32'
  desc 'check', 'Review documentation on the Google Android device and inspect the configuration on the Google Android device to enable audit logging.

This validation procedure is performed on only on the MDM Administration Console. 

On the MDM console, do the following:

1. Open the User restrictions.
2. Open user settings.
3. Select "Enable security logging".
4. Select "Enable network logging".

If the MDM console device policy is not set to enable audit logging, this is a finding.'
  desc 'fix', 'Configure the Google Android 10 to enable audit logging.

On the MDM console:

1. Open the User restrictions.
2. Open user settings.
3. Select "Enable security logging".
4. Select "Enable network logging".'
  impact 0.5
  ref 'DPMS Target Google Android 10.x'
  tag check_id: 'C-97797r1_chk'
  tag severity: 'medium'
  tag gid: 'V-98957'
  tag rid: 'SV-108061r1_rule'
  tag stig_id: 'GOOG-10-005505'
  tag gtitle: 'PP-MDF-302370'
  tag fix_id: 'F-104633r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000370', 'CCI-001851']
  tag nist: ['CM-6 b', 'CM-6 (1)', 'AU-4 (1)']
end
