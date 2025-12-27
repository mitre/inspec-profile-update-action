control 'SV-222653' do
  title 'The application development team must follow a set of coding standards.'
  desc 'Coding standards are guidelines established by the development team or individual developers that recommend programming style, practices and methods.  The coding standards employed will vary based upon the programming language that is being used to develop the application and the development team.

Coding standards often cover the use of white space characters, variable naming conventions, function naming conventions, and comment styles.  Implementing coding standards provides many benefits to the development process.  These benefits include code readability, coding consistency among both individual and teams of developers as well as ease of code integration.  

The following are examples of what will typically be in a coding standards document.  This list is an example of what one can expect to find in typical coding standard documents and is not a comprehensive list:

- Indent style conventions
- Naming conventions
- Line length conventions
- Comment conventions
- Programming best practices
- Programming style conventions

Coding standards allow developers to quickly adapt to code which has been developed by various members of a development team.  Coding standards are useful in the code review process as well as in situations where a team member leaves and duties must then be assigned to another team member.  

Code conforming to a standard format is easier to read, especially if someone other than the original developer is examining the code.  In addition, formatted code can be debugged and corrected faster than unformatted code.

Introducing coding standards can help increase the consistency, reliability, and security of the application by ensuring common programming structures and tasks are handled by similar methods, as well as, reducing the occurrence of common logic errors.'
  desc 'check', 'This requirement is meant to apply to developers or organizations that are doing application development work. If the organization operating the application under review is not doing the development or managing the development of the application, the requirement is not applicable.

Ask the application representative about their coding standards. Ask for a coding standards document, review the document and ask the developers if they are aware of and if they use the coding standards. Make a determination if the application developers follow the coding standard. 

If the developers do not follow a coding standard, or if a coding standard document does not exist, this is a finding.'
  desc 'fix', 'Create and maintain a coding standard process and documentation for developers to follow. 

Include programming best practices based on the languages being used for application development. Include items that should be standardized across the team that deals with how developers write their application code.'
  impact 0.3
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-36257r602334_chk'
  tag severity: 'low'
  tag gid: 'V-222653'
  tag rid: 'SV-222653r864580_rule'
  tag stig_id: 'APSC-DV-003215'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-36221r864580_fix'
  tag 'documentable'
  tag legacy: ['SV-85007', 'V-70385']
  tag cci: ['CCI-003233']
  tag nist: ['SA-15 a']
end
