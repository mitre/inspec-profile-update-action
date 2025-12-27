control 'SV-223152' do
  title 'Firefox must be configured to allow only TLS.'
  desc 'Use of versions prior to TLS 1.1 are not permitted. SSL 2.0 and SSL 3.0 contain a number of security flaws. These versions must be disabled in compliance with the Network Infrastructure and Secure Remote Computing STIGs.'
  desc 'check', 'Open a browser window, type "about:config" in the address bar.

Verify Preference Name "security.tls.version.min" is set to the value "2" and locked.
Verify Preference Name "security.tls.version.max" is set to the value "4" and locked.

Criteria: If the parameters are set incorrectly, this is a finding. 

If the settings are not locked, this is a finding.'
  desc 'fix', 'Configure the following parameters using the Mozilla.cfg file:

LockPref "security.tls.version.min" is set to "2".
LockPref "security.tls.version.max" is set to "4".'
  impact 0.5
  ref 'DPMS Target Mozilla Firefox'
  tag check_id: 'C-24825r531273_chk'
  tag severity: 'medium'
  tag gid: 'V-223152'
  tag rid: 'SV-223152r612236_rule'
  tag stig_id: 'DTBF030'
  tag gtitle: 'SRG-APP-000560'
  tag fix_id: 'F-24813r531274_fix'
  tag 'documentable'
  tag legacy: ['SV-16925', 'V-15983']
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']
end
