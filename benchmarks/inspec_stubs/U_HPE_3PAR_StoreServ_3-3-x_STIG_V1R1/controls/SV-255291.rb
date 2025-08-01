control 'SV-255291' do
  title 'The HPE 3PAR OS CIMserver process must be configured to use approved encryption and communications protocols to protect the confidentiality of remote access sessions.'
  desc 'Without confidentiality protection mechanisms, unauthorized individuals may gain access to sensitive information via a remote access session.

Remote access is access to DOD nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.

Encryption provides a means to secure the remote connection to prevent unauthorized access to the data traversing the remote access connection (e.g., RDP), thereby providing a degree of confidentiality. The encryption strength of a mechanism is selected based on the security categorization of the information.

The Common Information Model (CIM) protocol, and its associated Service Location Protocol (SLP) represent an additional, optional, management protocol for monitoring and controlling some aspects of the Storage Array. These settings limit the server to communications using TLS1.2.

'
  desc 'check', 'If the mission does not require CIM functionality this requirement is not applicable.

Verify if CIMserver is configured to run.
Use the command:
"cli% showcim"

If the Server column shows "Disabled", this is not applicable.

If the HTTP column shows "Enabled", this is a finding.

If the HTTPS column shows "Disabled", this is a finding.

Use the command:
"cli% showcim -pol" to display advanced configuration policies.

If the output contains "no_tls_strict", this is a finding.'
  desc 'fix', 'Verify if CIMserver is configured to run.
Use the command:
"cli% showcim"

If the Server column shows "Disabled", this is not applicable.

Temporarily stop the server using the command: "cli% stopcim -f"

Disable the HTTP listener, and enable the HTTPS listener, using the command: 
cli% setcim -http disable -https enable

Set the TLS policy to utilize only TLS1.2 with the following command:
cli% setcim -pol tls_strict

Restart the CIMserver using the command:
cli% startcim'
  impact 0.7
  ref 'DPMS Target HPE 3PAR StoreServ 3.3.x'
  tag check_id: 'C-58964r870190_chk'
  tag severity: 'high'
  tag gid: 'V-255291'
  tag rid: 'SV-255291r870192_rule'
  tag stig_id: 'HP3P-33-111100'
  tag gtitle: 'SRG-OS-000033-GPOS-00014'
  tag fix_id: 'F-58908r870191_fix'
  tag satisfies: ['SRG-OS-000033-GPOS-00014', 'SRG-OS-000096-GPOS-00050', 'SRG-OS-000112-GPOS-00057', 'SRG-OS-000074-GPOS-00042']
  tag 'documentable'
  tag cci: ['CCI-000068', 'CCI-000197', 'CCI-000382', 'CCI-001941']
  tag nist: ['AC-17 (2)', 'IA-5 (1) (c)', 'CM-7 b', 'IA-2 (8)']
end
