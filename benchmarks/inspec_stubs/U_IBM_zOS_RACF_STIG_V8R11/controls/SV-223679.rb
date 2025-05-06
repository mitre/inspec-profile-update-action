control 'SV-223679' do
  title 'IBM RACF must limit Write or greater access to libraries containing EXIT modules to system programmers only.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

'
  desc 'check', 'Examine the system for active exit modules. The system administrator may have to help for this. Third-party software products can determine standard and dynamic exits loaded in the system.

If all the exits are found within APF, LPA, and LINKLIST, this is Not Applicable.

If ESM data set rules for libraries that contain system exit modules restrict WRITE or greater access to only z/OS systems programming personnel, this is not a finding.

If the ESM data set rules for libraries that contain exit modules specify that all WRITE or greater access will be logged, this is not a finding.'
  desc 'fix', "Using the ESM, protect the data sets associated with all product exits installed in the z/OS environment. This reduces the potential of a hacker adding a routine to a library and possibly creating an exposure. Confirm that all exits are tracked using a CMP. Develop usermods to include the source/object code used to support the exits. Have systems programming personnel review all z/OS and other product exits to confirm that the exits are required and are correctly installed. 

Configure ESM Dataset rules for all WRITE or greater access to libraries containing z/OS and other system-level exits will be logged using the ACP's facilities. Only systems programming personnel will be authorized to update the libraries containing z/OS and other system-level exits."
  impact 0.7
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25352r868809_chk'
  tag severity: 'high'
  tag gid: 'V-223679'
  tag rid: 'SV-223679r868811_rule'
  tag stig_id: 'RACF-ES-000310'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25340r868810_fix'
  tag satisfies: ['SRG-OS-000080-GPOS-00048', 'SRG-OS-000259-GPOS-00100', 'SRG-OS-000324-GPOS-00125']
  tag 'documentable'
  tag legacy: ['V-98063', 'SV-107167']
  tag cci: ['CCI-000213', 'CCI-001499', 'CCI-002235']
  tag nist: ['AC-3', 'CM-5 (6)', 'AC-6 (10)']
end
