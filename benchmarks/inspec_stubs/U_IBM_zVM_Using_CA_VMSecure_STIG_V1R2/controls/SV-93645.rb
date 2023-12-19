control 'SV-93645' do
  title 'IBM z/VM TCP/IP config file INTERNALCLIENTPARMS statement must be properly configured.'
  desc 'Remote access services, such as those providing remote access to network devices and information systems, which lack automated control capabilities, increase risk and make remote user access management difficult at best.

Remote access is access to DoD nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.

Operating system functionality (e.g., RDP) must be capable of taking enforcement action if the audit reveals unauthorized activity. Automated control of remote access sessions allows organizations to ensure ongoing compliance with remote access policies by enforcing connection rules of remote access applications on a variety of information system components (e.g., servers, workstations, notebook computers, smartphones, and tablets).

The INTERNALCLIENTPARMS statement is used to configure the Telnet server, an internal client of the TCPIP virtual machine.'
  desc 'check', 'Examine the TCP/IP config file “INTERNALCLIENTPARMS” statement.

If the following “INTERNALCLIENTPARMS” sub statement are included, this is not a finding.

PORT Num not 20 or 21
SECURECONNECTION REQUIRED
CLIENTCERTCHECK FULL'
  desc 'fix', 'Configure the TCP/IP config “INTERNALCLIENTPARM” statement to include the following:

PORTNUM <secure FTP PORT Number>
SECURECONNECTION REQUIRED
CLIENTCERTCHECK FULL'
  impact 0.5
  ref 'DPMS Target z/VM Using CA VM:Secure'
  tag check_id: 'C-78525r1_chk'
  tag severity: 'medium'
  tag gid: 'V-78939'
  tag rid: 'SV-93645r1_rule'
  tag stig_id: 'IBMZ-VM-001060'
  tag gtitle: 'SRG-OS-000297-GPOS-00115'
  tag fix_id: 'F-85689r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002314']
  tag nist: ['AC-17 (1)']
end
