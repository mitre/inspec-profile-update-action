control 'SV-207284' do
  title 'The Exchange IMAP4 service must be disabled.'
  desc 'The IMAP4 protocol is not approved for use within the DoD. It uses a clear-text-based user name and password and does not support the DoD standard for PKI for email access. User name and password could easily be captured from the network, allowing a malicious user to access other system features. Uninstalling or disabling the service will prevent the use of the IMAP4 protocol.'
  desc 'check', "Open the Windows Power Shell and enter the following command:

Get-ItemProperty 'hklm:\\system\\currentcontrolset\\services\\MSExchangeIMAP4be' | Select Start

Note: The hklm:\\system\\currentcontrolset\\services\\MSExchangeIMAP4 value must be in quotes.

If the value of Start is not set to 4, this is a finding."
  desc 'fix', 'Open the Windows Power Shell and enter the following command:

services.msc

Navigate to and double-click on Microsoft Exchange IMAP4 Backend.

Click on the "General" tab.

In the Startup Type: dropdown, select Disabled.

Click the OK button.'
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2013 Mailbox Server'
  tag check_id: 'C-7542r393365_chk'
  tag severity: 'medium'
  tag gid: 'V-207284'
  tag rid: 'SV-207284r615936_rule'
  tag stig_id: 'EX13-MB-000090'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-7542r393366_fix'
  tag 'documentable'
  tag legacy: ['SV-84597', 'V-69975']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
