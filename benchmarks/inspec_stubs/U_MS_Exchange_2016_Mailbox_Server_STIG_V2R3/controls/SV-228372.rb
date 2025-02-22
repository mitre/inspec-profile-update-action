control 'SV-228372' do
  title 'The Exchange Post Office Protocol 3 (POP3) service must be disabled.'
  desc 'POP3 is not approved for use within the DoD. It uses a clear-text-based user name and password and does not support the DoD standard for PKI for email access. User name and password could easily be captured from the network, allowing a malicious user to access other system features. Uninstalling or disabling the service will prevent the use of POP3.'
  desc 'check', %q(Open the Windows Power Shell and enter the following command:

Get-ItemProperty 'hklm:\system\currentcontrolset\services\MSExchangePOP3' | Select Start

Note: The hklm:\system\currentcontrolset\services\MSExchangePOP3 value must be in single quotes.

If the value of "Start" is not set to "4", this is a finding.)
  desc 'fix', 'Open the Windows Power Shell and enter the following command:

services.msc

Navigate to and double-click on "Microsoft Exchange POP3 Backend".

Click on the "General" tab.

In the "Startup Type" dropdown, select "Disabled".

Click the "OK" button.'
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2016 Mailbox Server'
  tag check_id: 'C-30605r496912_chk'
  tag severity: 'medium'
  tag gid: 'V-228372'
  tag rid: 'SV-228372r612748_rule'
  tag stig_id: 'EX16-MB-000190'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-30590r496913_fix'
  tag 'documentable'
  tag legacy: ['SV-95369', 'V-80659']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
