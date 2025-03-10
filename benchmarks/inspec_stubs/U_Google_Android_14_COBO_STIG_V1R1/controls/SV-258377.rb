control 'SV-258377' do
  title 'Google Android 14 must be configured to enable audit logging.'
  desc 'Audit logs enable monitoring of security-relevant events and subsequent forensics when breaches occur. To be useful, administrators must have the ability to view the audit logs.

SFR ID: FMT_SMF_EXT.1.1 #32'
  desc 'check', 'Inspect the configuration on the managed Google Android 14 device to enable audit logging.

This validation procedure is performed only on the EMM Administration Console. 

On the EMM console:

COBO and COPE:

1. Open "Device owner management" section.
2. Verify that "Enable security logging" is toggled to "ON".

If the EMM console device policy is not set to enable audit logging, this is a finding.'
  desc 'fix', 'Configure the Google Android 14 device to enable audit logging.

On the EMM console:

COBO and COPE:

1. Open "Device owner management" section.
2. Toggle "Enable security logging" to "ON".'
  impact 0.5
  ref 'DPMS Target Google Android 14 COBO'
  tag check_id: 'C-62118r928154_chk'
  tag severity: 'medium'
  tag gid: 'V-258377'
  tag rid: 'SV-258377r928156_rule'
  tag stig_id: 'GOOG-14-002800'
  tag gtitle: 'PP-MDF-993300'
  tag fix_id: 'F-62042r928155_fix'
  tag 'documentable'
  tag cci: ['CCI-000154']
  tag nist: ['AU-6 (4)']
end
