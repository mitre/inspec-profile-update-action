control 'SV-93475' do
  title 'Tanium must be configured to communicate using TLS 1.2 Strict Only.'
  desc 'Without protection of the transmitted information, confidentiality and integrity may be compromised since unprotected communications can be intercepted and either read or altered.

This requirement applies only to those applications that are either distributed or can allow access to data non-locally. Use of this requirement will be limited to situations where the data owner has a strict requirement for ensuring data integrity and confidentiality is maintained at every step of the data transfer and handling process. When transmitting data, applications need to leverage transmission protection mechanisms, such as TLS, SSL VPNs, or IPsec. FIPS 140-2 approved TLS versions must be enabled, and non-FIPS-approved SSL versions must be disabled. NIST SP 800-52 defines the approved TLS versions for government applications.

Communication paths outside the physical protection of a controlled boundary are exposed to the possibility of interception and modification. Protecting the confidentiality and integrity of organizational information can be accomplished by physical means (e.g., employing physical distribution systems) or by logical means (e.g., employing cryptographic techniques). If physical means of protection are employed, then logical means (cryptography) do not have to be employed, and vice versa.'
  desc 'check', %q(Access the Tanium Server interactively.

Log on with an account with administrative privileges to the server.

Access the server's registry by typing: "regedit". Press "Enter".

Navigate to: HKEY_LOCAL_MACHINE >> SYSTEM >> CurrentControlSet >> Control >> SecurityProviders >> SCHANNEL >> Protocols >> SSL 3.0 >> Server

Name: DisabledByDefault
Type: REG_DWORD
Data: 0x0000001 (hex)

If the value for "DisabledByDefault" is not set to "1" and "Type" is not configured to "REG_DWORD" or does not exist, this is a finding.

Name: Enabled
Type: REG_DWORD
Data: 0x00000000 (hex)

If the value for "Enabled" is not set to "0" and "Type" is not configured to "REG_DWORD" or does not exist, this is a finding.)
  desc 'fix', %q(Access the Tanium Server interactively.

Log on with an account with administrative privileges to the server.

Access the server's registry by typing: "regedit". Press "Enter".

Navigate to: HKEY_LOCAL_MACHINE >> SYSTEM >> CurrentControlSet >> Control >> SecurityProviders >> SCHANNEL >> Protocols >> SSL 3.0 >> Server

Right-click in the right window pane.

Select: New >> DWORD (32-bit) Value

In the "Name" field, enter "DisabledByDefault" and press "Enter".

Right-click on the newly created "Name" and select "Modify..."

Enter "1" in "Value data:" and ensure that under "Base" the "Hexadecimal" radio button is selected. Click "OK".

Right-click in the right window pane. 

Select: New >> DWORD (32-bit) Value

In the "Name" field, enter "Enabled" and press "Enter".

Right-click on the newly created "Name" and select "Modify..."

Leave the default value of "0" in "Value data:" and ensure that under "Base" the "Hexadecimal" radio button is selected. Click "OK".)
  impact 0.5
  ref 'DPMS Target Tanium 7.0'
  tag check_id: 'C-78345r1_chk'
  tag severity: 'medium'
  tag gid: 'V-78769'
  tag rid: 'SV-93475r1_rule'
  tag stig_id: 'TANS-SV-000074'
  tag gtitle: 'SRG-APP-000439'
  tag fix_id: 'F-85511r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']
end
