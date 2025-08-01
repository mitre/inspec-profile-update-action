control 'SV-43990' do
  title 'The Microsoft Exchange POP3 service must be disabled.'
  desc 'The POP3 protocol is not approved for use within the DoD. It uses a clear text based user name and password and does not support the DoD standard for PKI for email access. User name and password could easily be captured from the network allowing malicious user to access other system features. Uninstalling or disabling the service will prevent the use of the POP3 protocol.'
  desc 'check', "Open the Windows Power Shell and enter the following command:

Get-ItemProperty 'hklm:\\system\\currentcontrolset\\services\\MSExchangePOP3' | Select Start

If the value of 'Start' is not set to '4', this is a finding."
  desc 'fix', "Open the Windows Power Shell and enter the following command:

services.msc

Double click the 'Microsoft Exchange POP3' service and select the General tab.

Set the 'Startup Type'  to 'Disabled', click ok."
  impact 0.5
  ref 'DPMS Target Microsoft Exchange Server 2010'
  tag check_id: 'C-41676r1_chk'
  tag severity: 'medium'
  tag gid: 'V-33570'
  tag rid: 'SV-43990r1_rule'
  tag stig_id: 'Exch-1-008'
  tag gtitle: 'Exch-1-008'
  tag fix_id: 'F-37461r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
end
