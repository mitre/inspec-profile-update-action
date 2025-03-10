control 'SV-222612' do
  title 'The application must not be vulnerable to overflow attacks.'
  desc 'A buffer overflow occurs when a program exceeds the amount of data allocated to a buffer. The buffer is a sequential section of memory and when the data is written outside the memory bounds, the program can crash or malicious code can be executed.

Security safeguards employed to protect memory include, for example, data execution prevention and address space layout randomization. Data execution prevention safeguards can either be hardware-enforced or software-enforced with hardware providing the greater strength of mechanism.

Buffer overflows can manifest as stack overflows, heap overflows integer overflows and format string overflows. Each type of overflow is dependent upon the underlying application language and the context in which the overflow is executed.

Integer overflows can lead to infinite looping when loop index variables are compromised and cause a denial of service.  If the integer is used in data references, the data can become corrupt. Also, using the integer in memory allocation can cause buffer overflows, and a denial of service.  Integers used in access control mechanisms can potentially trigger buffer overflows, which can be used to execute arbitrary code. 

Almost all known web servers, application servers, and web application environments are susceptible to buffer overflows. Proper validation of user input is required to mitigate the risk. Notably, limiting the size of the strings a user is allowed to input to a program to a predetermined, acceptable length.

A code review, static code analysis or active vulnerability or fuzz testing are methods used to identify overflows within application code.'
  desc 'check', 'Review the application documentation and architecture.

Interview the application admin and identify the most recent code testing and analysis that has been conducted.

Review the test results; verify configuration of analysis tools are set to check for the existence of overflows. This includes but is not limited to buffer overflows, stack overflows, heap overflows, integer overflows and format string overflows.

If overflows are identified in the test results, verify the latest test results are being used, if not, ensure remediation has been completed.

If the test results show overflows exist and no remediation evidence is presented, or if test results are not available, this is a finding.'
  desc 'fix', 'Design the application to use a language or compiler that performs automatic bounds checking.

Use an abstraction library to abstract away risky APIs.

Use compiler-based canary mechanisms such as StackGuard, ProPolice, and the Microsoft Visual Studio/GS flag.

Use OS-level preventative functionality and control user input validation.

Patch applications when overflows are identified in vendor products.'
  impact 0.7
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-36254r602325_chk'
  tag severity: 'high'
  tag gid: 'V-222612'
  tag rid: 'SV-222612r864579_rule'
  tag stig_id: 'APSC-DV-002590'
  tag gtitle: 'SRG-APP-000450'
  tag fix_id: 'F-36218r864579_fix'
  tag 'documentable'
  tag legacy: ['SV-84899', 'V-70277']
  tag cci: ['CCI-002824']
  tag nist: ['SI-16']
end
