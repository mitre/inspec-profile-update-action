control 'SV-84425' do
  title 'Exchange Send Fatal Errors to Microsoft must be disabled.'
  desc 'It is detrimental for applications to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

Applications are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions). 

Examples of non-essential capabilities include, but are not limited to, advertising software or browser plug-ins not related to requirements or providing a wide array of functionality not required for every mission, but cannot be disabled.

Customer Experience reports in Exchange will result in outbound traffic that may be identified by an eavesdropper. For this reason, the Customer Experience reports to Microsoft must not be sent.'
  desc 'check', 'Open the Exchange Management Shell and enter the following command:

Get-ExchangeServer –status | Select Name, Identity, ErrorReportingEnabled

For each Exchange server, if the value of ErrorReportingEnabled is not set to False, this is a finding.'
  desc 'fix', "Open the Exchange Management Shell and enter the following command:

Set-ExchangeServer -Identity <'IdentityName'>  -ErrorReportingEnabled $false

Note: The <IdentityName> value must be in quotes.

Repeat the procedure for each Identity."
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2013 Edge Transport Server'
  tag check_id: 'C-70255r1_chk'
  tag severity: 'medium'
  tag gid: 'V-69803'
  tag rid: 'SV-84425r1_rule'
  tag stig_id: 'EX13-EG-000055'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-76015r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
