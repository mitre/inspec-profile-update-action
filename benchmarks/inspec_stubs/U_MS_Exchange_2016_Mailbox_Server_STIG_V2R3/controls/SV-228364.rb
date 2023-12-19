control 'SV-228364' do
  title 'Exchange Send Fatal Errors to Microsoft must be disabled.'
  desc 'It is detrimental for applications to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

Applications are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions).

Examples of non-essential capabilities include but are not limited to advertising software or browser plug-ins not related to requirements or providing a wide array of functionality not required for every mission but that cannot be disabled.

All system errors in Exchange will result in outbound traffic that may be identified by an eavesdropper. For this reason, the "Report Fatal Errors to Microsoft" feature must be disabled.'
  desc 'check', 'Open the Exchange Management Shell and enter the following command:

Get-ExchangeServer –status | Select Name, Identity, ErrorReportingEnabled

For each Exchange Server, if the value of "ErrorReportingEnabled" is not set to "False", this is a finding.'
  desc 'fix', "Open the Exchange Management Shell and enter the following command:

Set-ExchangeServer -Identity <'IdentityName'> -ErrorReportingEnabled $false

Note: The <IdentityName> value must be in single quotes.

Repeat the process for each Exchange Server."
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2016 Mailbox Server'
  tag check_id: 'C-30597r496888_chk'
  tag severity: 'medium'
  tag gid: 'V-228364'
  tag rid: 'SV-228364r612748_rule'
  tag stig_id: 'EX16-MB-000110'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-30582r496889_fix'
  tag 'documentable'
  tag legacy: ['SV-95353', 'V-80643']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
