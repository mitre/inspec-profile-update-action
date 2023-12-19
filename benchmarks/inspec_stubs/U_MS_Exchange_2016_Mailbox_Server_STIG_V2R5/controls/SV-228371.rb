control 'SV-228371' do
  title 'The Exchange Internet Message Access Protocol 4 (IMAP4) service must be disabled.'
  desc 'IMAP4 is not approved for use within the DoD. It uses a clear-text-based user name and password and does not support the DoD standard for PKI for email access. User name and password could easily be captured from the network, allowing a malicious user to access other system features. Uninstalling or disabling the service will prevent the use of the IMAP4 protocol.'
  desc 'check', %q(Note: This requirement applies to IMAP4. IMAP Secure is not restricted and does not apply to this requirement.

Open the Windows Power Shell and enter the following command:

Get-ItemProperty 'hklm:\system\currentcontrolset\services\MSExchangeIMAP4' | Select Start

Note: The hklm:\system\currentcontrolset\services\MSExchangeIMAP4 value must be in single quotes.

If the value of "Start" is not set to "4", this is a finding.)
  desc 'fix', 'Open the Windows Power Shell and enter the following command:

services.msc

Navigate to and double-click on "Microsoft Exchange IMAP4 Backend".

Click on the "General" tab.

In the "Startup Type" dropdown, select "Disabled".

Click the "OK" button.'
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2016 Mailbox Server'
  tag check_id: 'C-30604r572118_chk'
  tag severity: 'medium'
  tag gid: 'V-228371'
  tag rid: 'SV-228371r879587_rule'
  tag stig_id: 'EX16-MB-000180'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-30589r496910_fix'
  tag 'documentable'
  tag legacy: ['SV-95367', 'V-80657']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
