control 'SV-255295' do
  title 'The HPE 3PAR OS WSAPI process must be configured to use approved encryption and communications protocols to protect the confidentiality of remote access sessions.'
  desc 'Without confidentiality protection mechanisms, unauthorized individuals may gain access to sensitive information via a remote access session.

Remote access is access to DOD nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.

Encryption provides a means to secure the remote connection to prevent unauthorized access to the data traversing the remote access connection (e.g., RDP), thereby providing a degree of confidentiality. The encryption strength of a mechanism is selected based on the security categorization of the information.

The WSAPI provides an, optional, REST interface for programmatic monitoring and control of the array operations and configuration. These configuration settings confine the server to using only TLS1.2.

'
  desc 'check', 'If the mission does not require WSAPI functionality, this requirement is not applicable.

Verify if WSAPI is configured to run.
Use the command:
cli% showwsapi -d

If "Service State" shows "Disabled", this is not applicable.

If "HTTP State" shows "Enabled", this is a finding.

If "HTTPS State" shows "Disabled", this is a finding.

If "Policy" contains "no_tls_strict", this is a finding.'
  desc 'fix', 'Verify if WSAPI is configured to run. Use the command:
cli% showwsapi -d

If "Service State" shows "Disabled", this is not applicable.

Temporarily stop the WSAPI server with the command:
cli% stopwsapi -f

To disable the HTTP listener, and enable the HTTPS listener, use the command:
cli% setwsapi -http disable -https enable

To set the TLS policy to TLSv1.2 only, use the command:
cli% setwsapi -pol tls_strict

Restart the server with the following command:
cli% startwsapi'
  impact 0.7
  ref 'DPMS Target HPE 3PAR StoreServ 3.3.x'
  tag check_id: 'C-58968r870202_chk'
  tag severity: 'high'
  tag gid: 'V-255295'
  tag rid: 'SV-255295r870204_rule'
  tag stig_id: 'HP3P-33-121100'
  tag gtitle: 'SRG-OS-000033-GPOS-00014'
  tag fix_id: 'F-58912r870203_fix'
  tag satisfies: ['SRG-OS-000033-GPOS-00014', 'SRG-OS-000096-GPOS-00050', 'SRG-OS-000112-GPOS-00057', 'SRG-OS-000074-GPOS-00042']
  tag 'documentable'
  tag cci: ['CCI-000068', 'CCI-000197', 'CCI-000382', 'CCI-001941']
  tag nist: ['AC-17 (2)', 'IA-5 (1) (c)', 'CM-7 b', 'IA-2 (8)']
end
