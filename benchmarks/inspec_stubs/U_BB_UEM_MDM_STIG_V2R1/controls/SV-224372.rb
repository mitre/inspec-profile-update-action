control 'SV-224372' do
  title 'The BlackBerry UEM server must be configured to communicate the following commands to the MDM Agent: read audit logs kept by the MD.'
  desc 'Audit logs enable monitoring of security-relevant events and subsequent forensics when breaches occur. For audit logs to be useful, administrators must have the ability to view them.

SFR ID: FMT_SMF.1.1(1) #19'
  desc 'check', 'Verify each Android device being managed by UEM has been configured to enable device auditing.

Verify the policy pushed by UEM to each Android device include "Enable auditing".

If auditing has not been enabled for each Android device being managed by UEM, this is a finding.'
  desc 'fix', 'This requirement is only applicable on Android devices and is configured via each Android device STIG (enabling device Auditing).

Enable device auditing for each Android device being managed by UEM using procedures in the Android STIG.'
  impact 0.5
  ref 'DPMS Target BlackBerry UEM'
  tag check_id: 'C-26049r539016_chk'
  tag severity: 'medium'
  tag gid: 'V-224372'
  tag rid: 'SV-224372r604136_rule'
  tag stig_id: 'BUEM-00-000110'
  tag gtitle: 'PP-MDM-411009'
  tag fix_id: 'F-26037r539017_fix'
  tag 'documentable'
  tag legacy: ['SV-111861', 'V-102899']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
