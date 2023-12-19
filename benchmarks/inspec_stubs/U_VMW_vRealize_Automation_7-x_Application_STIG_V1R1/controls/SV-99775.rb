control 'SV-99775' do
  title 'vRA must enable FIPS Mode.'
  desc 'Encryption is only as good as the encryption modules utilized. Unapproved cryptographic module algorithms cannot be verified and cannot be relied upon to provide confidentiality or integrity, and DoD data may be compromised due to weak algorithms. The use of TLS provides confidentiality of data in transit between the application server and client. FIPS 140-2 approved TLS versions include TLS V1.0 or greater. 

TLS must be enabled and non-FIPS-approved SSL versions must be disabled. NIST SP 800-52 specifies the preferred configurations for government systems.'
  desc 'check', 'Check that FIPS mode is enabled in the vRealize Automation virtual appliance management interface with the following steps:

1. Log on to the vRealize Automation virtual appliance management interface (vAMI): https://vrealize-automation-appliance-FQDN:5480
2. Select vRA Settings >> Host Settings.
3. Review the button under the Actions heading on the upper right to confirm that "enable FIPS" is selected.

If "enable FIPS" is not selected, this is a finding.

Alternately, check that FIPS mode is enabled in the command line using the following steps:

1. Log on to the console as root.
2. Run the command: vcac-vami fips status

If FIPS is not enabled, this is a finding.'
  desc 'fix', 'FIPS mode in the vRealize Automation virtual appliance management interface can be enabled with the following steps:

1. Log on to the vRealize Automation virtual appliance management interface (vAMI): https://vrealize-automation-appliance-FQDN:5480
2. Select vRA Settings >> Host Settings.
3. Click the button under the "Actions" heading on the upper right to enable or disable FIPS.
4. Click "Yes" to restart the vRealize Automation appliance.

Alternately, FIPS mode can be enabled in the command line using the following steps:
1. Log on to the console as root.
2. Run the command: vcac-vami fips enable'
  impact 0.7
  ref 'DPMS Target vRealize Automation 7.x Application'
  tag check_id: 'C-88817r2_chk'
  tag severity: 'high'
  tag gid: 'V-89125'
  tag rid: 'SV-99775r1_rule'
  tag stig_id: 'VRAU-AP-000265'
  tag gtitle: 'SRG-APP-000179-AS-000129'
  tag fix_id: 'F-95867r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
