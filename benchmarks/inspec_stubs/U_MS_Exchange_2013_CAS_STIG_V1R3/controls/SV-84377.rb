control 'SV-84377' do
  title 'Exchange POP3 service must be disabled.'
  desc 'The POP3 protocol is not approved for use within the DoD. It uses a clear text based user name and password and does not support the DoD standard for PKI for email access. User name and password could easily be captured from the network allowing malicious users to access other system features. Uninstalling or disabling the service will prevent the use of the POP3 protocol.'
  desc 'check', "Open the Windows PowerShell and enter the following command:

Get-ItemProperty 'hklm:\\system\\currentcontrolset\\services\\MSExchangePOP3' | Select Start

Note: The hklm:\\system\\currentcontrolset\\services\\MSExchangePOP3 value must be in quotes.

If the value of Start is not set to 4, this is a finding."
  desc 'fix', 'Open the Windows PowerShell and enter the following command:

services.msc

Navigate to and double-click on Microsoft Exchange POP3 Backend.

Click on the General tab.

In the Startup Type: dropdown, select Disabled.

Click the OK button.'
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2013 Client Access Server'
  tag check_id: 'C-70199r1_chk'
  tag severity: 'medium'
  tag gid: 'V-69755'
  tag rid: 'SV-84377r1_rule'
  tag stig_id: 'EX13-CA-000100'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-75961r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
