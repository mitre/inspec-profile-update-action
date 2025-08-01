control 'SV-222605' do
  title 'The application must protect from canonical representation vulnerabilities.'
  desc 'Canonical representation vulnerabilities can occur when a data conversion process does not convert the data to its simplest form resulting in the possible misrepresentation of the data.

The application may behave in an unexpected manner when acting on input that has not been sanitized or normalized.

Vulnerable application code is written to expect one form of data and executes its program logic on another form of data thereby creating instability or unexpected behavior.

The Open Web Application Security Project (OWASP) website provides test and remediation procedures that can be used for testing if vulnerability scan tools or results are not available.

The site is available by pointing your browser to https://www.owasp.org.'
  desc 'check', 'Review the application documentation and interview the application administrator for details regarding security assessment code reviews or vulnerability scans.

Review the scan results from the entire application. This can be provided as results from an automated code review or a vulnerability scanning tool.

Review the scan results to determine if there are any existing canonical representation vulnerabilities.

Review web server and application configuration.

The OWASP website provides the following test procedures:

"Investigate the web application to determine if it asserts an internal code page, locale, or culture.

If the default character set, locale is not asserted it will be one of the following:

HTTP Posts. Interesting tidbit: All HTTP posts are required to be ISO 8859-1, which will lose data for most double byte character sets. You must test your application with your supported browsers to determine if they pass in fully encoded double byte characters safely

HTTP Gets. Depends on the previously rendered page and per-browser implementations, but URL encoding is not properly defined for double byte character sets. IE can be optionally forced to do all submits as UTF-8 which is then properly canonicalized on the server

.NET: Unicode (little endian)

JSP implementations, such as Tomcat: UTF8 - see “javaEncoding” in web.xml by many servlet containers

Java: Unicode (UTF-16, big endian, or depends on the OS during JVM startup)

PHP: Set in php.ini, ISO 8859-1”

If the results are not provided or the application representative cannot demonstrate that the application does not use Unicode encoding, this is a finding.'
  desc 'fix', 'A suitable canonical form should be chosen and all user input canonicalized into that form before any authorization decisions are performed.

Security checks should be carried out after decoding is completed. Moreover, it is recommended to check that the encoding method chosen is a valid canonical encoding for the symbol it represents.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-36252r602319_chk'
  tag severity: 'medium'
  tag gid: 'V-222605'
  tag rid: 'SV-222605r561266_rule'
  tag stig_id: 'APSC-DV-002520'
  tag gtitle: 'SRG-APP-000251'
  tag fix_id: 'F-36216r602320_fix'
  tag 'documentable'
  tag legacy: ['SV-84885', 'V-70263']
  tag cci: ['CCI-001310']
  tag nist: ['SI-10']
end
