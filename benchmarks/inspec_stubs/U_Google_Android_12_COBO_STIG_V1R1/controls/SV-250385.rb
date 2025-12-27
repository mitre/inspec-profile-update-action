control 'SV-250385' do
  title 'Google Android 12 must be configured to enable audit logging.'
  desc 'Audit logs enable monitoring of security-relevant events and subsequent forensics when breaches occur. To be useful, Administrators must have the ability to view the audit logs.

SFR ID: FMT_SMF_EXT.1.1 #32'
  desc 'check', 'Inspect the configuration on the managed Google Android 12 device to enable audit logging.

This validation procedure is performed only on the EMM Administration Console. 

On the EMM console:

COBO and COPE:

1. Open "Device owner management" section.
2. Verify that "Enable security logging" is toggled to ON.

If the EMM console device policy is not set to enable audit logging, this is a finding.'
  desc 'fix', 'Configure the Google Android 12 device to enable audit logging.

On the EMM console:

COBO and COPE:

1. Open "Device owner management" section.
2. Toggle "Enable security logging" to ON.'
  impact 0.5
  ref 'DPMS Target Google Android 12 COBO'
  tag check_id: 'C-53820r796661_chk'
  tag severity: 'medium'
  tag gid: 'V-250385'
  tag rid: 'SV-250385r802707_rule'
  tag stig_id: 'GOOG-12-002800'
  tag gtitle: 'PP-MDF-990000'
  tag fix_id: 'F-53774r796662_fix'
  tag 'documentable'
  tag cci: ['CCI-000154']
  tag nist: ['AU-6 (4)']
end
