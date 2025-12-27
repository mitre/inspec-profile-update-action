control 'SV-84397' do
  title 'Exchange OWA must use https.'
  desc 'Without protection of the transmitted information, confidentiality and integrity may be compromised since unprotected communications can be intercepted and either read or altered.'
  desc 'check', 'If the exchange server does not provide OWA services, this check is Not Applicable.
If the exchange server does not provide external OWA services, https does not need to be assigned to external URL, it may be blank.
Open the Exchange Management Shell and enter the following command:

Get-OWAVirtualDirectory | Select Name, Identity, ExternalUrl, InternalUrl 

If the value returned is not both ExternalUrl and InternalUrl and these are not set to https://, this is a finding.'
  desc 'fix', "Open the Exchange Management Shell and enter the following command:

Set-OWAVirtualDirectory -Identity '<IdentityName>\\owa (Default Web Site)' -ExternalUrl 'https://URL' -InternalUrl 'https://URL'

Note: The <IdentityName>\\owa (default web site) value must be in quotes."
  impact 0.7
  ref 'DPMS Target Microsoft Exchange 2013 Client Access Server'
  tag check_id: 'C-70225r2_chk'
  tag severity: 'high'
  tag gid: 'V-69775'
  tag rid: 'SV-84397r2_rule'
  tag stig_id: 'EX13-CA-000150'
  tag gtitle: 'SRG-APP-000439'
  tag fix_id: 'F-75987r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']
end
