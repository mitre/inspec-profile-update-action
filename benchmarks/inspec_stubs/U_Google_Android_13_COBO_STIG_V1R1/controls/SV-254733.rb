control 'SV-254733' do
  title 'Google Android 13 must be configured to enable audit logging.'
  desc 'Audit logs enable monitoring of security-relevant events and subsequent forensics when breaches occur. To be useful, administrators must have the ability to view the audit logs.

SFR ID: FMT_SMF_EXT.1.1 #32'
  desc 'check', 'Inspect the configuration on the managed Google Android 13 device to enable audit logging.

This validation procedure is performed only on the EMM Administration Console. 

On the EMM console:

COBO and COPE:

1. Open "Device owner management" section.
2. Verify that "Enable security logging" is toggled to "ON".

If the EMM console device policy is not set to enable audit logging, this is a finding.'
  desc 'fix', 'Configure the Google Android 13 device to enable audit logging.

On the EMM console:

COBO and COPE:

1. Open "Device owner management" section.
2. Toggle "Enable security logging" to "ON".'
  impact 0.5
  ref 'DPMS Target Google Android 13 COBO'
  tag check_id: 'C-58344r862396_chk'
  tag severity: 'medium'
  tag gid: 'V-254733'
  tag rid: 'SV-254733r862398_rule'
  tag stig_id: 'GOOG-13-002800'
  tag gtitle: 'PP-MDF-990000'
  tag fix_id: 'F-58290r862397_fix'
  tag 'documentable'
  tag cci: ['CCI-000154']
  tag nist: ['AU-6 (4)']
end
