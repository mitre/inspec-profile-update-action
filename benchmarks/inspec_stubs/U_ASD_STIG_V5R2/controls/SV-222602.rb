control 'SV-222602' do
  title 'The application must protect from Cross-Site Scripting (XSS) vulnerabilities.'
  desc 'XSS attacks are essentially code injection attacks against the various language interpreters contained within the browser. XSS can be executed via HTML, JavaScript, VBScript, ActiveX; essentially any scripting language a browser is capable of processing.

XSS vulnerabilities are created when a website does not properly sanitize, escape, or encode user input. For example, "&lt;" is the HTML encoding for the "<" character. If the encoding is performed, the script code will not execute.

There are 3 parties involved in an XSS attack, the attacker, the trusted and vulnerable website, and the victim. An attacker will take advantage of a vulnerable website that does not properly validate user input by inserting malicious code into any data entry field.

When the victim visits the trusted website and clicks on the malicious link left by the attacker, the attacker’s script is executed in the victims browser with the trust permissions assigned to the site.

There are several different types of XSS attack and the complete details regarding XSS cannot be described completely here.

To address the issue of XSS, web application developers must escape, encode or otherwise validate all user input that is processed and output by the web server. They should also use web templates or a web development framework that provides the capability to encode or otherwise validate user input.

Examples of XSS vulnerabilities can be obtained from the Open Web Application Security Project (OWASP) website.
  
The site is available by pointing your browser to https://www.owasp.org.'
  desc 'check', %q(Review the application documentation and the vulnerability assessment scan results from automated vulnerability assessment tools.

Verify scan configuration settings include web-based applications settings which include XSS tests.

Review scan results for XSS vulnerabilities.

If the scan results indicate aspects of the application are vulnerable to XSS, request subsequent scan data that shows the XSS vulnerabilities previously detected have been fixed.

If results that show compliance are not available, request proof of any steps that have been taken to mitigate the risk. This can include using network-based IPS to detect and prevent XSS attacks from occurring.

If scan results are not available, perform manual testing in various data entry fields to determine if XSS exist.

Navigate through the web application as a regular user and identify any data entry fields where data can be input.

Input the following strings:

<script>alert('hello')</script>
<img src=x onerror="alert(document.cookie);"

If the script pop up box is displayed, or if scan reports show unremediated XSS results and no mitigating steps have been taken, this is a finding.)
  desc 'fix', 'Verify user input is validated and encode or escape user input to prevent embedded script code from executing.

Develop your application using a web template system or a web application development framework that provides auto escaping features rather than building your own escape logic.'
  impact 0.7
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-36251r602316_chk'
  tag severity: 'high'
  tag gid: 'V-222602'
  tag rid: 'SV-222602r561263_rule'
  tag stig_id: 'APSC-DV-002490'
  tag gtitle: 'SRG-APP-000251'
  tag fix_id: 'F-36215r602317_fix'
  tag 'documentable'
  tag legacy: ['SV-84879', 'V-70257']
  tag cci: ['CCI-001310']
  tag nist: ['SI-10']
end
