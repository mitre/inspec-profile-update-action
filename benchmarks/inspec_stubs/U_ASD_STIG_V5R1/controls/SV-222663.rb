control 'SV-222663' do
  title 'An Application Configuration Guide must be created and included with the application.'
  desc 'The Application Configuration Guide is any document or collection of documents used to configure the application.  These documents may be part of a user guide, secure configuration guide, or any guidance that satisfies the requirements provided herein.  

Configuration examples include but are not limited to:

 - Encryption Settings
 - PKI Certificate Configuration Settings
 - Password Settings
 - Auditing configuration
 - AD configuration
 - Backup and disaster recovery settings
 - List of hosting enclaves and network connection requirements
 - Deployment configuration settings 
 - Known security assumptions, implications, system level protections, best practices, and required permissions

Development systems, build systems, and test systems must operate in a standardized environment. These settings are to be documented in the Application Configuration Guide.

Examples include but are not limited to:

 - List of development systems, build systems, and test systems. 
 - Versions of compilers used
 - Build options when creating applications and components
 - Versions of COTS software (used as part of the application)
 - Operating systems and versions
 - For web applications, which browsers and what versions are supported.
 
All deployment configuration settings are to be documented in the Application Configuration Guide and the Application Configuration Guide must be made available to application hosting providers and application/system administrators.'
  desc 'check', 'Interview the application administrator.  Request and review the Application Configuration Guide. 

Verify the configuration guide at a minimum provides configuration details for the following examples.  The examples provided herein are not intended to limit the configuration settings that are documented in the guide.

Configuration examples include but are not limited to:

 - Encryption Settings
 - PKI Certificate Configuration Settings
 - Password Settings
 - Auditing configuration
 - AD configuration
 - Backup and disaster recovery settings
 - List of hosting enclaves and network connection requirements
 - Deployment configuration settings 
 - Known security assumptions, implications, system level protections, best practices, and required permissions

Review the Application Configuration Guide and determine if development systems are documented.  If no development is being performed where the application is hosted, this part of the requirement is NA.

Development systems, build systems, and test systems must operate in a standardized environment.

Examples include but are not limited to:

 - List of development systems, build systems, and test systems. 
 - Versions of compilers used
 - Build options when creating applications and components
 - Versions of COTS software (used as part of the application)
 - Operating systems and versions
 - For web applications, which browsers and what versions are supported.

If there is no application configuration guide included with the application, this is a finding.'
  desc 'fix', 'Create the application configuration guide in accordance with configuration examples provided in the vulnerability discussion and check.

Verify the application configuration guide is distributed along  with the application.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24333r493897_chk'
  tag severity: 'medium'
  tag gid: 'V-222663'
  tag rid: 'SV-222663r508029_rule'
  tag stig_id: 'APSC-DV-003285'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-24322r493898_fix'
  tag 'documentable'
  tag legacy: ['V-70405', 'SV-85027']
  tag cci: ['CCI-003124', 'CCI-000366']
  tag nist: ['SA-5 a 1', 'CM-6 b']
end
