control 'SV-222609' do
  title 'The application must not be subject to input handling vulnerabilities.'
  desc 'A common application vulnerability is unpredictable behavior due to improper input validation. This requirement guards against adverse or unintended system behavior caused by invalid inputs, where information system responses to the invalid input may be disruptive or cause the system to fail into an unsafe state.

Data received from the user should always be suspected as being malicious and always validated prior to using it as input to the application.

Some examples of input methods:

- Forms Data
- URL parameters
- Hidden Fields
- Cookies
- HTTP Headers or anything in the HTTP request
- Client data entry fields

Items to validate:

- Out of range values/Boundary 
- Data length 
- Validate types of characters allowed
- Whitelist validation for known good data input while denying all other input.

Other recommendations include: 

- Using drop down menus for lists
- Validating input on the server, not on the client.

If validating on the client, also validate on the server:

- Using regular expressions to validate input
- Using HTML filter libraries that implement input validation tasks.'
  desc 'check', 'Review the application documentation and interview the application administrator.

If working with the developer, request documentation on their development processes and what their standard operating procedure is for sanitizing all application input.

Identify the latest vulnerability scan results.

Review the scan results and scan configuration settings.

Verify the scan was configured to identify input validation vulnerabilities.

If the scan results detected high risk vulnerabilities, verify a more recent scan shows remediation of the vulnerabilities is available for examination.

Review any risk acceptance documentation that indicates the ISSO has reviewed and accepted the risk.

If the vulnerability scan is not configured to test for input validation vulnerabilities if the most recent scan results show that high risk input validation vulnerabilities exist and a documented risk acceptance from the ISSO is not available, or if the scan results do not exist, this is a finding.'
  desc 'fix', 'Follow best practice when accepting user input and verify that all input is validated before the application processes the input.

Remediate identified vulnerabilities and obtain documented risk acceptance for those issues that cannot be remediated immediately.'
  impact 0.7
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24279r561267_chk'
  tag severity: 'high'
  tag gid: 'V-222609'
  tag rid: 'SV-222609r561269_rule'
  tag stig_id: 'APSC-DV-002560'
  tag gtitle: 'SRG-APP-000447'
  tag fix_id: 'F-24268r561268_fix'
  tag 'documentable'
  tag legacy: ['SV-84893', 'V-70271']
  tag cci: ['CCI-002754']
  tag nist: ['SI-10 (3)']
end
