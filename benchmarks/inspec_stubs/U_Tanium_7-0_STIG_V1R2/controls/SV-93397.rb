control 'SV-93397' do
  title 'The Tanium Module server must be installed on a separate system.'
  desc 'Unauthorized access to the Tanium Server is protected by disabling the Module Server service on the Tanium Server and by configuring the Module Server on a separate system.

When X509 smartcard certificates (CAC or PIV tokens) are used for access to the Tanium Server, the Tanium Module server must be on a separate system.

In order to restrict access to the Tanium Server resulting from an attack on the Module Server, it is recommended that the Tanium Module Server be installed on a separate system or VM from the Tanium Server. Adding to this recommendation, if the Tanium Server is configured to accept X509 Smartcard certificates (also referred to as CAC or PIV tokens) in lieu of username/password logon, the requirement becomes explicit and the Tanium Module Server must be installed on a separate system or VM.'
  desc 'check', 'Note: If the server being validated is the Tanium Module server, this check is "Not Applicable".

Access the Tanium Server interactively.

Log on with an account with administrative privileges to the server.

Click "Start" and access Server Manager.

Select Local Server.

In upper right corner, click "Tools".

Select "Services".

If the Tanium Module Server service is "Running", this is a finding.'
  desc 'fix', 'Access the Tanium Server interactively.

Log on with an account with administrative privileges to the server.

Click "Start" and access Server Manager.

Select "Local Server".

In the upper right corner, click "Tools".

Select "Services".

Disable the Tanium Module Server service.'
  impact 0.5
  ref 'DPMS Target Tanium 7.0'
  tag check_id: 'C-78261r1_chk'
  tag severity: 'medium'
  tag gid: 'V-78691'
  tag rid: 'SV-93397r1_rule'
  tag stig_id: 'TANS-SV-000023'
  tag gtitle: 'SRG-APP-000211'
  tag fix_id: 'F-85427r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001082']
  tag nist: ['SC-2']
end
