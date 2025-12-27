control 'SV-223821' do
  title 'IBM z/OS must be configured to restrict all TCP/IP ports to ports, protocols, and/or services as defined in the PPSM CAL and vulnerability assessments.'
  desc 'Remote access services, such as those providing remote access to network devices and information systems, which lack automated control capabilities, increase risk and make remote user access management difficult at best.

Remote access is access to DoD nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.

Operating system functionality (e.g., RDP) must be capable of taking enforcement action if the audit reveals unauthorized activity. Automated control of remote access sessions allows organizations to ensure ongoing compliance with remote access policies by enforcing connection rules of remote access applications on a variety of information system components (e.g., servers, workstations, notebook computers, smartphones, and tablets).'
  desc 'check', 'Refer the TCP/IP PROFILE DD statement to determine the TCP/IP Ports. If the PROFILE DD statement is not supplied, use the default search order to find the PROFILE data set. 

See the IP Configuration Guide for a description of the search order for PROFILE.TCPIP. 

If the all the Ports included in the configuration are restricted to the ports, protocols, and/or services, as defined in the Ports, Protocols, and Services Management (PPSM) Category Assurance List (CAL) and vulnerability assessments, this is not a finding.'
  desc 'fix', 'Configure TCP/IP PROFILE port definitions to adhere to ports, protocols, and/or services, as defined in the Ports, Protocols, and Services Management (PPSM) Category Assurance List (CAL) and vulnerability assessments.'
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25494r515151_chk'
  tag severity: 'medium'
  tag gid: 'V-223821'
  tag rid: 'SV-223821r853633_rule'
  tag stig_id: 'RACF-TC-000020'
  tag gtitle: 'SRG-OS-000297-GPOS-00115'
  tag fix_id: 'F-25482r515152_fix'
  tag 'documentable'
  tag legacy: ['SV-107453', 'V-98349']
  tag cci: ['CCI-002314']
  tag nist: ['AC-17 (1)']
end
