control 'SV-84399' do
  title 'Exchange OWA must have S/MIME Certificates enabled.'
  desc 'Without protection of the transmitted information, confidentiality and integrity may be compromised since unprotected communications can be intercepted and either read or altered. 

This requirement applies only to those applications that are either distributed or can allow access to data non-locally. Use of this requirement will be limited to situations where the data owner has a strict requirement for ensuring data integrity and confidentiality is maintained at every step of the data transfer and handling process. When transmitting data, applications need to leverage transmission protection mechanisms, such as TLS, SSL VPNs, or IPsec.

Communication paths outside the physical protection of a controlled boundary are exposed to the possibility of interception and modification.'
  desc 'check', 'Open the Exchange Management Shell and enter the following command: 

Get-OWAVirtualDirectory | Select Name, Identity, SmimeEnabled

If the value returned is not set to True, this is a finding.'
  desc 'fix', "Open the Exchange Management Shell and enter the following command:

Set-OWAVirtualDirectory -Identity '<IdentityName>\\owa (Default Web Site)' -SmimeEnabled $true

Note: The <ServerName>\\owa (Default Web Site) value must be in quotes."
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2013 Client Access Server'
  tag check_id: 'C-70227r1_chk'
  tag severity: 'medium'
  tag gid: 'V-69777'
  tag rid: 'SV-84399r1_rule'
  tag stig_id: 'EX13-CA-000155'
  tag gtitle: 'SRG-APP-000440'
  tag fix_id: 'F-75989r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002421']
  tag nist: ['SC-8 (1)']
end
