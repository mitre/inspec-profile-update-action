control 'SV-222587' do
  title 'The application must protect the confidentiality and integrity of stored information when required by DoD policy or the information owner.'
  desc 'Information at rest refers to the state of information when it is located on a secondary storage device (e.g., disk drive and tape drive) within an organizational information system. Mobile devices, laptops, desktops, and storage devices can be either lost or stolen, and the contents of their data storage (e.g., hard drives and non-volatile memory) can be read, copied, or altered. 

Applications and application users generate information throughout the course of their application use, including data that is stored in areas of volatile memory.  Volatile memory must not be overlooked when assigning protections.

This requirement addresses protection of user-generated data, as well as, operating system-specific configuration data. 

Applications must employ mechanisms to achieve confidentiality and integrity protections, as appropriate, in accordance with the security category and/or classification of the information.

This can include segmenting and controlling access to the data such as utilizing file permissions to restrict access, using role based controls to restrict access or applying a cryptographic hash to the data and evaluating hash values for changes made to data.'
  desc 'check', 'Review the application documentation and interview the application administrator.

Identify the data processed by the application and the accompanying data protection requirements.

Determine if the data owner has specified stored data protection requirements.

Determine if the application is processing publicly releasable, FOUO or classified stored data.

Determine if the application configuration information contains sensitive information.

Access the data repository and have the application administrator, application developer or designer identify the data integrity and confidentiality protections utilized to protect stored data.

If the application processes classified data or if the data owner has specified data protection requirements and the application administrator is unable to demonstrate how the data is protected, this is a finding.'
  desc 'fix', 'Identify data elements that require protection. Document the data types and specify protection requirements and methods used.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24257r493669_chk'
  tag severity: 'medium'
  tag gid: 'V-222587'
  tag rid: 'SV-222587r879642_rule'
  tag stig_id: 'APSC-DV-002330'
  tag gtitle: 'SRG-APP-000231'
  tag fix_id: 'F-24246r493670_fix'
  tag 'documentable'
  tag legacy: ['SV-84847', 'V-70225']
  tag cci: ['CCI-001199']
  tag nist: ['SC-28']
end
