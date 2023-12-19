control 'SV-84363' do
  title 'Exchange must not send Customer Experience reports to Microsoft.'
  desc 'It is detrimental for applications to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

Applications are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions). 

Examples of non-essential capabilities include, but are not limited to, advertising software or browser plug-ins not related to requirements or providing a wide array of functionality not required for every mission, but cannot be disabled.'
  desc 'check', 'Open the Exchange Management Shell and enter the following command:

Get-OrganizationConfig | Select Name, Identity, CustomerFeedbackEnabled 

If the value for CustomerFeedbackEnabled is not set to False, this is a finding.'
  desc 'fix', 'Open the Exchange Management Shell and enter the following command:

Set-OrganizationConfig -CustomerFeedbackEnabled $false'
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2013 Client Access Server'
  tag check_id: 'C-70185r1_chk'
  tag severity: 'medium'
  tag gid: 'V-69741'
  tag rid: 'SV-84363r1_rule'
  tag stig_id: 'EX13-CA-000070'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-75947r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
