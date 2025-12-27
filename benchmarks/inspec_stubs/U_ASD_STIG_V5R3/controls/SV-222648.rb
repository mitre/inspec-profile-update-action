control 'SV-222648' do
  title 'An application code review must be performed on the application.'
  desc 'A code review is a systematic evaluation of computer source code conducted for the purposes of identifying and remediating the security flaws in the software.

This requirement is meant to apply to developers or organizations that are doing application development work and have the responsibility for maintaining the application source code.

Examples of security flaws include but are not limited to:

- format string exploits
- memory leaks 
- buffer overflows 
- race conditions
- sql injection
- dead/unused/commented code
- input validation exploits

The code review is conducted during the application development phase, this allows discovered security issues to be corrected prior to release.

Code reviews performed after the development phase must eventually go back to development for correction so conducting the code review during development is the logical and preferred action.

Automated code review tools are to be used whenever reviewing application source code. These tools are often incorporated into Integrated Development Environments (IDE) so code reviews can be conducted during all stages of the development life cycle. Periodically reviewing code during the development phase makes transition to a production environment easier as flaws are continually identified and addressed during the development phase rather than en masse at the end of the development effort.

Code review processes and the tools used to conduct the code review analysis will vary depending upon application architecture and the development languages utilized.

In addition to automated testing, manual code reviews may also be used to validate or augment automated code review results. Larger projects will have a large code base and will require the use of automated code review tools in order to achieve complete code review coverage.

A manual code review may consist of a peer review wherein other programmers on the team manually examine source code and automated code review results for known flaws that introduce security bugs into the application.

As with any testing, there is no single best approach and the tests must be tailored to the application architecture. Use of automated tools along with manual review of code and testing results is considered a best practice when conducting code reviews. This method is the most likely way to ensure the maximum number of errors are caught and addressed prior to implementing the application in a production environment.'
  desc 'check', 'This requirement is meant to apply to developers or organizations that are doing the application development work and have the responsibility for maintaining the application source code.  Otherwise, the requirement is not applicable.

Review the system documentation and ask the application representative to describe the code review process or provide documentation outlining the organizations code review process.

If code reviews are conducted with software tools, have the application representative provide the latest code review report for the application.

Ensure the code review looks for all known security flaws including but not limited to:

- format string exploits
- memory leaks
- buffer overflows
- race conditions
- sql injection
- dead/unused/commented code
- input validation exploits

If the organization does not conduct code reviews on the application that attempt to identify all known and potential security issues, or if code review results are not available for review, this is a finding.'
  desc 'fix', 'Conduct and document code reviews on the application during development and identify and remediate all known and potential security vulnerabilities prior to releasing the application.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24318r493852_chk'
  tag severity: 'medium'
  tag gid: 'V-222648'
  tag rid: 'SV-222648r879887_rule'
  tag stig_id: 'APSC-DV-003170'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-24307r493853_fix'
  tag 'documentable'
  tag legacy: ['SV-84997', 'V-70375']
  tag cci: ['CCI-003187']
  tag nist: ['SA-11 (4)']
end
