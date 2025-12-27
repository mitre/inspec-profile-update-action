control 'SV-82915' do
  title 'Mainframe Products must implement cryptographic mechanisms to protect the confidentiality of nonlocal maintenance and diagnostic communications.'
  desc 'Privileged access contains control and configuration information which is particularly sensitive, so additional protections are necessary. This is maintained by using cryptographic mechanisms to protect confidentiality.

Nonlocal maintenance and diagnostic activities are those activities conducted by individuals communicating through a network, either an external network (e.g., the Internet) or an internal network. Local maintenance and diagnostic activities are those activities carried out by individuals physically present at the information system or information system component and not communicating across a network connection. 

The application can meet this requirement through leveraging a cryptographic module.'
  desc 'check', 'If the Mainframe Product has no function or capability for nonlocal maintenance, this is not applicable.

Examine installation and configuration settings.

If the Mainframe Product does not use FIPS 140 compliant modules to protect the confidentiality of nonlocal maintenance and diagnostic communications, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product to use FIPS 140 compliant modules to protect the confidentiality of nonlocal maintenance and diagnostic communications.'
  impact 0.5
  ref 'DPMS Target SRG-APP-MFPR'
  tag check_id: 'C-68957r1_chk'
  tag severity: 'medium'
  tag gid: 'V-68425'
  tag rid: 'SV-82915r1_rule'
  tag stig_id: 'SRG-APP-000412-MFP-000261'
  tag gtitle: 'SRG-APP-000412-MFP-000261'
  tag fix_id: 'F-74541r1_fix'
  tag 'documentable'
  tag cci: ['CCI-003123']
  tag nist: ['MA-4 (6)']
end
