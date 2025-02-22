control 'SV-251686' do
  title 'Splunk Enterprise must be installed in FIPS mode to implement NIST FIPS-approved cryptography for all cryptographic functions.'
  desc 'FIPS 140-2 precludes the use of unvalidated cryptography for the cryptographic protection of sensitive or valuable data within Federal systems. Unvalidated cryptography is viewed by NIST as providing no protection to the information or data. In effect, the data would be considered unprotected plaintext. If the agency specifies that the information or data be cryptographically protected, then FIPS 140-2 is applicable. In essence, if cryptography is required, it must be validated. Cryptographic modules that have been approved for classified use may be used in lieu of modules that have been validated against the FIPS 140-2 standard.

'
  desc 'check', 'Run the following command from the server command line:
Note: Run this command as the account of last resort, as no other local user accounts should exist.

splunk show fips-mode -auth <username>:<password>

Verify that the command returns FIPS mode enabled.

If the command returns FIPS mode disabled, this is a finding.'
  desc 'fix', 'FIPS 140-2 mode must be enabled during initial installation. If not enabled, it requires a reinstall or upgrade of the application.

Add the following line to the $SPLUNK_HOME/etc/splunk-launch.conf file during the installation process and before the initial start of Splunk Enterprise:

SPLUNK_COMMON_CRITERIA=1
SPLUNK_FIPS=1
# Do not generate python byte code
PYTHONDONTWRITEBYTECODE=1

This will enable FIPS mode before the initial startup.'
  impact 0.7
  ref 'DPMS Target Splunk Enterprise 8.x for Linux'
  tag check_id: 'C-55124r808292_chk'
  tag severity: 'high'
  tag gid: 'V-251686'
  tag rid: 'SV-251686r879609_rule'
  tag stig_id: 'SPLK-CL-000390'
  tag gtitle: 'SRG-APP-000172-AU-002550'
  tag fix_id: 'F-55078r808293_fix'
  tag satisfies: ['SRG-APP-000172-AU-002550', 'SRG-APP-000179-AU-002670', 'SRG-APP-000514-AU-002890']
  tag 'documentable'
  tag cci: ['CCI-000197', 'CCI-000803', 'CCI-002450']
  tag nist: ['IA-5 (1) (c)', 'IA-7', 'SC-13 b']
end
