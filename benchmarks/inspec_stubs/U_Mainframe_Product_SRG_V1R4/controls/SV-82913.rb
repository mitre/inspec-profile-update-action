control 'SV-82913' do
  title 'Mainframe Products must implement cryptographic mechanisms to protect the integrity of nonlocal maintenance and diagnostic communications.'
  desc 'Privileged access contains control and configuration information which is particularly sensitive, so additional protections are necessary. This is maintained by using cryptographic mechanisms to protect integrity.

Nonlocal maintenance and diagnostic activities are those activities conducted by individuals communicating through a network, either an external network (e.g., the Internet) or an internal network. Local maintenance and diagnostic activities are those activities carried out by individuals physically present at the information system or information system component and not communicating across a network connection. 

This requirement applies to hardware/software diagnostic test equipment or tools. This requirement does not cover hardware/software components that may support information system maintenance, yet are a part of the system (e.g., the software implementing "ping," "ls," "ipconfig," or the hardware and software implementing the monitoring port of an Ethernet switch).

The application can meet this requirement through leveraging a cryptographic module.'
  desc 'check', 'If the Mainframe Product has no function or capability for nonlocal maintenance, this is not applicable.

Examine installation and configuration settings.

If the Mainframe Product does not use FIPS 140 compliant modules to protect the integrity of nonlocal maintenance and diagnostic communications, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product to use FIPS 140 compliant modules to protect the integrity of nonlocal maintenance and diagnostic communications.'
  impact 0.5
  ref 'DPMS Target SRG-APP-MFPR'
  tag check_id: 'C-68955r1_chk'
  tag severity: 'medium'
  tag gid: 'V-68423'
  tag rid: 'SV-82913r1_rule'
  tag stig_id: 'SRG-APP-000411-MFP-000260'
  tag gtitle: 'SRG-APP-000411-MFP-000260'
  tag fix_id: 'F-74539r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002890']
  tag nist: ['MA-4 (6)']
end
