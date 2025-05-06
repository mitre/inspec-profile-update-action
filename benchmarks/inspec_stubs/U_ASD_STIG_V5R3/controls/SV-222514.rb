control 'SV-222514' do
  title 'The applications must limit privileges to change the software resident within software libraries.'
  desc 'If the application were to allow any user to make changes to software libraries, then those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process.

This requirement applies to applications with software libraries that are accessible and configurable, as in the case of interpreted languages. Software libraries also include privileged programs which execute with escalated privileges. Only qualified and authorized individuals will be allowed to obtain access to information system components for purposes of initiating changes, including upgrades and modifications.'
  desc 'check', 'Review the application documentation and interview the application administrator to identify the application architecture.

Identify application folders where application libraries are stored.

Review permissions of application folders and library files contained with the folders to ensure file permissions restrict access to authorized users or processes.

Access application configuration settings.

Examine settings for capability to update software libraries or extend application functionality via the application.

Review user roles and access rights within the application to determine if access to this capability is restricted to authorized users.

If file restrictions do not limit write access to library files and if the application does not restrict access to library update functionality, this is a finding.'
  desc 'fix', 'Configure the application OS file permissions to restrict access to software libraries and configure the application to restrict user access regarding software library update functionality to only authorized users or processes.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24184r493450_chk'
  tag severity: 'medium'
  tag gid: 'V-222514'
  tag rid: 'SV-222514r879586_rule'
  tag stig_id: 'APSC-DV-001440'
  tag gtitle: 'SRG-APP-000133'
  tag fix_id: 'F-24173r493451_fix'
  tag 'documentable'
  tag legacy: ['V-69511', 'SV-84133']
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
