control 'SV-255259' do
  title 'The SSMC web server must perform RFC 5280-compliant certification path validation.'
  desc "A certificate's certification path is the path from the end entity certificate to a trusted root certification authority (CA). Certification path validation is necessary for a relying party to make an informed decision regarding acceptance of an end entity certificate. Certification path validation includes checks such as certificate issuer trust, time validity and revocation status for each certificate in the certification path. Revocation status information for CA and subject certificates in a certification path is commonly provided via certificate revocation lists (CRLs) or online certificate status protocol (OCSP) responses."
  desc 'check', 'To verify SSMC always validates PKI certificates of all remote hosts that it connects to, in accordance with RFC 5280, do the following:

1. Log on to ssmc appliance as ssmcadmin and escape to general bash shell.

2. Execute the following command:
$ grep ^ssmc.tls.trustManager.enabled /opt/hpe/ssmc/ssmcbase/resources/ssmc.properties

ssmc.tls.trustManager.enabled=true

If the command output does not show the property ssmc.tls.trustManager.enabled as set to "true", this is a finding.'
  desc 'fix', 'Configure SSMC to always validate PKI certificates in accordance with RFC 5280 for all connections to remote hosts (as a client) by doing the following:

1. Log on to ssmc appliance as ssmcadmin and escape to general bash shell.

2. Edit (using vi editor) file /opt/hpe/ssmc/ssmcbase/resources/ssmc.properties and set the property:
ssmc.tls.trustManager.enabled=true

3. Save the file and exit.

4. Type "config_appliance" to return to TUI. Restart (stop and start) SSMC services using TUI menu option 2.'
  impact 0.5
  ref 'DPMS Target HPE 3PAR SSMC Web Server'
  tag check_id: 'C-58872r916427_chk'
  tag severity: 'medium'
  tag gid: 'V-255259'
  tag rid: 'SV-255259r916429_rule'
  tag stig_id: 'SSMC-WS-010100'
  tag gtitle: 'SRG-APP-000175-WSR-000095'
  tag fix_id: 'F-58816r916428_fix'
  tag 'documentable'
  tag cci: ['CCI-000185']
  tag nist: ['IA-5 (2) (b) (1)']
end
