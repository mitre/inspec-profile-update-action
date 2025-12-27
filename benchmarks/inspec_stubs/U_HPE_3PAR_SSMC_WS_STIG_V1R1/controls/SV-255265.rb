control 'SV-255265' do
  title 'SSMC web server must enable strict two-factor authentication for access to the webUI.'
  desc 'Accounts secured with only a password are subject to multiple forms of attack, from brute force, to social engineering. By enforcing strict two-factor authentication, this reduces the risk of account compromise by requiring an additional factor that is not a password.
Strict two-factor authentication is enabled by default. However, this is enforced only when two-factor authentication is configured and active. This blocks access to web administrator console for ssmcadmin as this is a local account authenticated using password credentials. To allow access to administrator console, disable this strict two-factor authentication setting.'
  desc 'check', 'Verify that SSMC is configured to enforce strict two-factor authentication by doing the following:

1. Log on to SSMC appliance as ssmcadmin.

2. Navigate to the Advanced Features section of the TUI by pressing "9" then "2".

If the Advanced Features sections displays "Enable strict two-factor authentication", this is a finding.

3. Escape to the bash shell by pressing "X".

4. Check the two-factor authentication property values in the /opt/hpe/ssmc/ssmcbase/resources/ssmc.properties file with the following command:

$ grep ^security.twofactor /opt/hpe/ssmc/ssmcbase/resources/ssmc.properties
security.twofactor.strict = true
security.twofactor.enabled = true

If the properties for "security.twofactor.strict" and "security.twofactor.enabled" are not set to "true" or are missing, this is a finding.'
  desc 'fix', 'Configure SSMC to enforce strict two-factor authentication by doing the following:

1. Log on to SSMC appliance as ssmcadmin.

2. Navigate to the Advanced Features section of the TUI by pressing "9" then "2". Press "1"  to "Enable strict two-factor authentication" and "Y" to confirm.

3. Escape to the bash shell by pressing "X".

4. Enable and enforce strict two-factor authentication by setting these two properties in /opt/hpe/ssmc/ssmcbase/resources/ssmc.properties:

security.twofactor.enabled = true
security.twofactor.strict = true'
  impact 0.5
  ref 'DPMS Target HPE 3PAR SSMC Web Server'
  tag check_id: 'C-58878r869962_chk'
  tag severity: 'medium'
  tag gid: 'V-255265'
  tag rid: 'SV-255265r869964_rule'
  tag stig_id: 'SSMC-WS-020010'
  tag gtitle: 'SRG-APP-000516-WSR-000174'
  tag fix_id: 'F-58822r869963_fix'
  tag 'documentable'
  tag cci: ['CCI-000765', 'CCI-000766']
  tag nist: ['IA-2 (1)', 'IA-2 (2)']
end
