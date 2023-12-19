control 'SV-223914' do
  title 'CA-TSS must limit WRITE or greater access to libraries containing EXIT modules to system programmers only.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

'
  desc 'check', "Examine the system for active exit modules. You may need the system administrator's help for this. There are third-party software products that can determine standard and dynamic exits loaded in the system. 

If all the exits are found within APF, LPA, and LINKLIST, this is not applicable.

If ESM data set rules for libraries that contain system exit modules restrict WRITE or greater access to only z/OS systems programming personnel, this is not a finding.

If the ESM data set rules for libraries that contain exit modules specify that all WRITE or greater access will be logged, this is not a finding."
  desc 'fix', "Using the ESM, protect the data sets associated with all product exits installed in the z/OS environment. This reduces the potential of a hacker adding a routine to a library and possibly creating an exposure. Confirm that all exits are tracked using a CMP. Develop usermods to include the source/object code used to support the exits. Have systems programming personnel review all z/OS and other product exits to confirm that the exits are required and are correctly installed. 

Configure ESM data set rules for all WRITE or greater access to libraries containing z/OS and other system-level exits will be logged using the ACP's facilities. Only systems programming personnel will be authorized to update the libraries containing z/OS and other system level exits."
  impact 0.7
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25587r868939_chk'
  tag severity: 'high'
  tag gid: 'V-223914'
  tag rid: 'SV-223914r868941_rule'
  tag stig_id: 'TSS0-ES-000410'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25575r868940_fix'
  tag satisfies: ['SRG-OS-000080-GPOS-00048', 'SRG-OS-000259-GPOS-00100', 'SRG-OS-000324-GPOS-00125']
  tag 'documentable'
  tag legacy: ['SV-107639', 'V-98535']
  tag cci: ['CCI-000213', 'CCI-001499', 'CCI-002235']
  tag nist: ['AC-3', 'CM-5 (6)', 'AC-6 (10)']
end
