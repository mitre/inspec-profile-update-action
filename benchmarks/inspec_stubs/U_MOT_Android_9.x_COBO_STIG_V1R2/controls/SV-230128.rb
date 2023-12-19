control 'SV-230128' do
  title 'The Motorola Android Pie must be configured to enable audit logging.'
  desc 'Audit logs enable monitoring of security-relevant events and subsequent forensics when breaches occur. For the logs to be useful, Administrators must have the ability to view the audit logs.

SFR ID: FMT_SMF_EXT.1.1 #32'
  desc 'check', 'Review documentation on the Motorola Android device and inspect the configuration on the Motorola Android device to enable audit logging.

This validation procedure is performed on only on the MDM Administration Console. 

On the MDM console: 
1. Open the Restrictions settings.
2. Open User settings.
3. Select "Enable security logging".
4. Select "Enable network logging".

If the MDM console device policy is not set to enable audit logging, this is a finding.'
  desc 'fix', 'Configure the Motorola Android Pie to enable audit logging.

On the MDM console: 
1. Open the Restrictions settings.
2. Open User settings.
3. Select "Enable security logging".
4. Select "Enable network logging".'
  impact 0.5
  ref 'DPMS Target Motorola Android 9.x COBO STIG'
  tag check_id: 'C-58133r859748_chk'
  tag severity: 'medium'
  tag gid: 'V-230128'
  tag rid: 'SV-230128r859750_rule'
  tag stig_id: 'MOTO-09-005505'
  tag gtitle: 'GOOG-09-005505'
  tag fix_id: 'F-58082r859749_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000370', 'CCI-001851']
  tag nist: ['CM-6 b', 'CM-6 (1)', 'AU-4 (1)']
end
