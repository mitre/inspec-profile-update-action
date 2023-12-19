control 'SV-255272' do
  title 'The HPE 3PAR OS must be configured to restrict the encryption algorithms and protocols to comply with DOD-approved encryption to protect the confidentiality and integrity of remote access sessions.'
  desc 'Without confidentiality protection mechanisms, unauthorized individuals may gain access to sensitive information via a remote access session.

Remote access is access to DOD nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.

Encryption provides a means to secure the remote connection to prevent unauthorized access to the data traversing the remote access connection (e.g., RDP), thereby providing a degree of confidentiality. The encryption strength of a mechanism is selected based on the security categorization of the information.

The HPE 3PAR OS supports communication security in compliance with DOD requirements. These include TLS1.2 protocols, encryption supplied by a FIPS140-2 library, and using specific cipher suites in a subset of the CNSA guidelines. Configuration is required to restrict the available algorithms to a subset of those approved by the DOD.

'
  desc 'check', 'Verify that insecure ports are disabled.

cli%  setnet disableports yes

To confirm the operation, enter
"cli%  y"
and press "Enter".

If an error is reported, this is a finding.

If available, a port scan can also verify that only secure ports are open. From a command shell on a Linux workstation in the operational environment, enter the following command:
cli%  nmap -sT -sU -sV --version-all -vv -p1 -65535 <ip address of storage system> 

If any Port is listed other than SSHD(22), NTP(123), SNMP(161,162), 3PAR Mgmt Intfc (5783), CIM (5989/configurable), or WSAPI (8088/configurable), this is a finding.'
  desc 'fix', 'To disable all unencrypted ports, use the command:

cli%  setnet disableports yes

To confirm the operation, enter
"cli%  y"
and press "Enter".'
  impact 0.7
  ref 'DPMS Target HPE 3PAR StoreServ 3.3.x'
  tag check_id: 'C-58945r870133_chk'
  tag severity: 'high'
  tag gid: 'V-255272'
  tag rid: 'SV-255272r870135_rule'
  tag stig_id: 'HP3P-33-001100'
  tag gtitle: 'SRG-OS-000033-GPOS-00014'
  tag fix_id: 'F-58889r870134_fix'
  tag satisfies: ['SRG-OS-000033-GPOS-00014', 'SRG-OS-000096-GPOS-00050', 'SRG-OS-000112-GPOS-00057', 'SRG-OS-000250-GPOS-00093', 'SRG-OS-000480-GPOS-00227', 'SRG-OS-000393-GPOS-00173', 'SRG-OS-000394-GPOS-00174', 'SRG-OS-000423-GPOS-00187', 'SRG-OS-000424-GPOS-00188', 'SRG-OS-000425-GPOS-00189', 'SRG-OS-000426-GPOS-00190', 'SRG-OS-000297-GPOS-00115', 'SRG-OS-000074-GPOS-00042']
  tag 'documentable'
  tag cci: ['CCI-000068', 'CCI-000197', 'CCI-000366', 'CCI-000382', 'CCI-001453', 'CCI-002314', 'CCI-002418', 'CCI-002420', 'CCI-002421', 'CCI-002422', 'CCI-002890', 'CCI-003123']
  tag nist: ['AC-17 (2)', 'IA-5 (1) (c)', 'CM-6 b', 'CM-7 b', 'AC-17 (2)', 'AC-17 (1)', 'SC-8', 'SC-8 (2)', 'SC-8 (1)', 'SC-8 (2)', 'MA-4 (6)', 'MA-4 (6)']
end
