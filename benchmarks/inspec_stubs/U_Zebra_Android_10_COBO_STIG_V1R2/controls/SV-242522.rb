control 'SV-242522' do
  title 'Zebra Android 10 must be configured to enable audit logging.'
  desc 'Audit logs enable monitoring of security-relevant events and subsequent forensics when breaches occur. For audit logs to be useful, Administrators must have the ability to view the logs.

SFR ID: FMT_SMF_EXT.1.1 #32'
  desc 'check', 'Review documentation on the Zebra Android 10 device and inspect the configuration on the Zebra Android 10 device to enable audit logging.

This validation procedure is performed on only on the MDM Administration Console. 

On the MDM console:
1. Open the User restrictions.
2. Open User settings.
3. Select "Enable security logging".
4. Select "Enable network logging".

If the MDM console device policy is not set to enable audit logging, this is a finding.'
  desc 'fix', 'Configure the Zebra Android 10 device to enable audit logging.

On the MDM console:
1. Open the User restrictions.
2. Open User settings.
3. Select "Enable security logging".
4. Select "Enable network logging".'
  impact 0.5
  ref 'DPMS Target Zebra Android 10 COBO'
  tag check_id: 'C-45797r714409_chk'
  tag severity: 'medium'
  tag gid: 'V-242522'
  tag rid: 'SV-242522r852813_rule'
  tag stig_id: 'ZEBR-10-005505'
  tag gtitle: 'PP-MDF-302370'
  tag fix_id: 'F-45754r714410_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000370', 'CCI-001851']
  tag nist: ['CM-6 b', 'CM-6 (1)', 'AU-4 (1)']
end
