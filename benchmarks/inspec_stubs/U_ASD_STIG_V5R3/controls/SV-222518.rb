control 'SV-222518' do
  title 'The application must be configured to disable non-essential capabilities.'
  desc 'It is detrimental for applications to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

Applications are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions).

Examples of non-essential capabilities include, but are not limited to, advertising software or browser plug-ins not related to requirements or providing a wide array of functionality not required for every mission, but cannot be disabled.'
  desc 'check', "Review the application guidance, application requirements documentation, and interview the application administrator.

Identify the application's operational requirements and what services the application is intended to provide users.

Review the overall application features and functionality via the user interface.

Review and identify installed application software modules via configuration settings.

Using the relevant OS commands, identify services running on the system and have the application administrator identify the services related to the application.

If the application is operating with extraneous capabilities that have not been defined as required in order to meet mission objectives, this is a finding."
  desc 'fix', "Disable application extraneous application functionality that is not required in order to fulfill the application's mission."
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24188r493462_chk'
  tag severity: 'medium'
  tag gid: 'V-222518'
  tag rid: 'SV-222518r879587_rule'
  tag stig_id: 'APSC-DV-001500'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-24177r493463_fix'
  tag 'documentable'
  tag legacy: ['SV-84141', 'V-69519']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
