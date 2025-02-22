control 'SV-221600' do
  title 'Splunk Enterprise must be installed with FIPS mode enabled, to implement NIST FIPS 140-2 approved ciphers for all cryptographic functions.'
  desc 'FIPS 140-2 precludes the use of unvalidated cryptography for the cryptographic protection of sensitive or valuable data within Federal systems. Unvalidated cryptography is viewed by NIST as providing no protection to the information or data. In effect, the data would be considered unprotected plaintext. If the agency specifies that the information or data be cryptographically protected, then FIPS 140-2 is applicable. In essence, if cryptography is required, it must be validated. Cryptographic modules that have been approved for classified use may be used in lieu of modules that have been validated against the FIPS 140-2 standard.'
  desc 'check', 'Select the Search and Reporting App.

Execute a search query using the following:

| rest splunk_server=local /services/server/info | fields fips_mode

Verify that the report returns fips_mode = 1.

If the query returns 0, this is a finding.'
  desc 'fix', 'FIPS 140-2 mode MUST be enabled during installation. If not enabled, it requires a reinstall or upgrade of the application.

The installer must be executed from the command line so that it can be passed the LAUNCHSPLUNK=0 parameter.

This allows Splunk to install and not automatically start up after install.

Example: msiexec /i <splunkinstaller.msi> LAUNCHSPLUNK=0

Using a text editor, edit $SPLUNK_HOME/etc/splunk-launch.conf file, add the line SPLUNK_FIPS=1 to it, restart the server, and then recheck this requirement.'
  impact 0.7
  ref 'DPMS Target Splunk Enterprise 7.x for Windows'
  tag check_id: 'C-23315r416257_chk'
  tag severity: 'high'
  tag gid: 'V-221600'
  tag rid: 'SV-221600r879885_rule'
  tag stig_id: 'SPLK-CL-000010'
  tag gtitle: 'SRG-APP-000514-AU-002890'
  tag fix_id: 'F-23304r416258_fix'
  tag 'documentable'
  tag legacy: ['SV-111305', 'V-102349']
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
