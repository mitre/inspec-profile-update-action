control 'SV-235051' do
  title 'The Honeywell Mobility Edge Android Pie device must be configured to enable audit logging.'
  desc 'Audit logs enable monitoring of security-relevant events and subsequent forensics when breaches occur. To be useful, Administrators must have the ability to view the audit logs.

SFR ID: FMT_SMF_EXT.1.1 #32'
  desc 'check', 'Review documentation on the Honeywell Android device and inspect the configuration on the Honeywell Android device to enable audit logging.

This validation procedure is performed on only on the MDM Administration console. 

On the MDM console:
1. Open the Restrictions settings.
2. Open User Settings.
3. Select "Enable security logging".
4. Select "Enable network logging".

If the MDM console device policy is not set to enable audit logging, this is a finding.'
  desc 'fix', 'Configure the Honeywell Android Pie to enable audit logging.

On the MDM console:
1. Open the Restrictions settings.
2. Open User Settings.
3. Select "Enable security logging".
4. Select "Enable network logging".'
  impact 0.5
  ref 'DPMS Target Honeywell Android 9.x COBO'
  tag check_id: 'C-38239r623063_chk'
  tag severity: 'medium'
  tag gid: 'V-235051'
  tag rid: 'SV-235051r626530_rule'
  tag stig_id: 'HONW-09-005505'
  tag gtitle: 'PP-MDF-302370'
  tag fix_id: 'F-38202r623064_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000370', 'CCI-001851']
  tag nist: ['CM-6 b', 'CM-6 (1)', 'AU-4 (1)']
end
