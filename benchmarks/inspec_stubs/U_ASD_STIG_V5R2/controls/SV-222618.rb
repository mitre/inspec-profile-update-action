control 'SV-222618' do
  title 'Unsigned Category 1A mobile code must not be used in the application in accordance with DoD policy.'
  desc 'Use of un-trusted Level 1A mobile code technologies can introduce security vulnerabilities and malicious code into the client system.

1A code is defined as:

- ActiveX controls
- Mobile code script (JavaScript, VBScript)
- Windows Scripting Host (WSH) (downloaded via URL or email)

When JavaScript and VBScript execute within the browser they are Category 3, however, when they execute in WSH, they are 1A.'
  desc 'check', 'Review the application documentation and interview the application administrator to identify any mobile code that is provided by the application for client consumption.

If the application does not contain mobile code, or if the mobile code executes within the client browser, this is not applicable.

The URL of the application must be added to the Trusted Sites zone. This is accomplished via the Tools, Internet Options, and “Security” Tab.

Select the “Trusted Sites” zone.
Click the “sites” button.
Enter the URL into the text box below the “Add this site to this zone” message.
Click "Add”.
Click “OK”.

Note: This requires administrator privileges to add URL to sites on a STIG compliant workstation.

Next, test the application. This testing should include functional testing from all major components of the application.

If mobile code is in use, the browser will prompt to download the control. At the download prompt, the browser will indicate that code has been digitally signed.

If the code has not been signed or the application warns that a control cannot be invoked due to security settings, this is a finding.'
  desc 'fix', 'Configure the application so Category 1A mobile code is signed.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24288r493762_chk'
  tag severity: 'medium'
  tag gid: 'V-222618'
  tag rid: 'SV-222618r508029_rule'
  tag stig_id: 'APSC-DV-002870'
  tag gtitle: 'SRG-APP-000206'
  tag fix_id: 'F-24277r493763_fix'
  tag 'documentable'
  tag legacy: ['SV-84911', 'V-70289']
  tag cci: ['CCI-001166']
  tag nist: ['SC-18 (1)']
end
