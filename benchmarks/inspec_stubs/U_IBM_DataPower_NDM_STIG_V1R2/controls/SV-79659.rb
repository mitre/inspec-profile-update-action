control 'SV-79659' do
  title 'The IBM DataPower Gateway must only allow the use of protocols that implement cryptographic mechanisms to protect the integrity and confidentiality of management communications.'
  desc 'This requires the use of secure protocols instead of their unsecured counterparts, such as SSH instead of telnet, SCP instead of FTP, and HTTPS instead of HTTP. If unsecured protocols (lacking cryptographic mechanisms) are used for sessions, the contents of those sessions will be susceptible to manipulation, potentially allowing alteration and hijacking of maintenance sessions.'
  desc 'check', 'Go to Network >> Management >> Telnet Service and ensure that no active Telnet configurations exist for device management. Other administrative interfaces (SSH, browser, XML Management) are run over secure protocols by default and cannot be changed. If Telnet configurations exist, this is a finding.'
  desc 'fix', 'Go to Network >> Management >> Telnet Service and ensure that no active Telnet configurations exist for device management. Other administrative interfaces (SSH, browser, XML Management) are run over secure protocols by default and cannot be changed.'
  impact 0.5
  ref 'DPMS Target IBM DataPower XI52 NDM'
  tag check_id: 'C-65797r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65169'
  tag rid: 'SV-79659r1_rule'
  tag stig_id: 'WSDP-NM-000117'
  tag gtitle: 'SRG-APP-000411-NDM-000330'
  tag fix_id: 'F-71109r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002890']
  tag nist: ['MA-4 (6)']
end
