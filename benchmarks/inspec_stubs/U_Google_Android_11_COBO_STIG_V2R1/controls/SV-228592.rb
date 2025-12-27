control 'SV-228592' do
  title 'Google Android 11 must be configured to enable audit logging.'
  desc 'Audit logs enable monitoring of security-relevant events and subsequent forensics when breaches occur. To be useful, Administrators must have the ability to view the audit logs.

SFR ID: FMT_SMF_EXT.1.1 #32'
  desc 'check', 'Review documentation on the Google Android device and inspect the configuration on the Google Android device to enable audit logging.

This validation procedure is performed on only on the EMM Administration Console. 

On the EMM console, do the following:
1. Open "Device owner management" section.
2. Verify that "Enable security logging" is toggled to On.

If the EMM console device policy is not set to enable audit logging, this is a finding.'
  desc 'fix', 'Configure the Google Android 11 device to enable audit logging.

On the EMM console:
1. Open "Device owner management" section.
2. Toggle "Enable security logging" to On.'
  impact 0.5
  ref 'DPMS Target Google Android 11 COBO'
  tag check_id: 'C-30827r505601_chk'
  tag severity: 'medium'
  tag gid: 'V-228592'
  tag rid: 'SV-228592r852659_rule'
  tag stig_id: 'GOOG-11-005505'
  tag gtitle: 'PP-MDF-302370'
  tag fix_id: 'F-30804r505602_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000370', 'CCI-001851']
  tag nist: ['CM-6 b', 'CM-6 (1)', 'AU-4 (1)']
end
