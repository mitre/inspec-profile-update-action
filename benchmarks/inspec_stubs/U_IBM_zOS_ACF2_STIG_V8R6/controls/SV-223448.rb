control 'SV-223448' do
  title 'CA-ACF2 must limit Write or greater access to Libraries containing EXIT modules to system programmers only.'
  desc 'Access control policies include: identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include: access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system.

This requirement applies to operating systems with software libraries that are accessible and configurable, as in the case of interpreted languages. Software libraries also include privileged programs which execute with escalated privileges. Only qualified and authorized individuals must be allowed to obtain access to information system components for purposes of initiating changes, including upgrades and modifications.

Privileged functions include, for example, establishing accounts, performing system integrity checks, or administering cryptographic key management activities. Non-privileged users are individuals that do not possess appropriate authorizations. Circumventing intrusion detection and prevention mechanisms or malicious code protection mechanisms are examples of privileged functions that require protection from non-privileged users.

'
  desc 'check', 'Examine the system for active exit modules. You may need system administrator help for this. Third-party software products can determine standard and dynamic exits loaded in the system. 

If all the exits are found within APF, LPA, and LINKLIST, this is not applicable.

If ESM data set rules for libraries that contain system exit modules restrict UPDATE and ALLOCATE access to only z/OS systems programming personnel, this is not a finding.

If the ESM data set rules for libraries that contain exit modules specify that all UPDATE and ALLOCATE access will be logged, this is not a finding.'
  desc 'fix', 'Using the ESM, protect the data sets associated with all product exits installed in the z/OS environment. This reduces the potential of a hacker adding a routine to a library and possibly creating an exposure. See that all exits are tracked using a CMP. Develop usermods to include the source/object code used to support the exits. Have Systems programming personnel review all z/OS and other product exits to confirm that the exits are required and are correctly installed. 

Configure ESM data set rules for all update and alter access to libraries containing z/OS and other system level exits will be logged using the ACP’s facilities. Only systems programming personnel will be authorized to update the libraries containing z/OS and other system level exits.'
  impact 0.7
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25121r504476_chk'
  tag severity: 'high'
  tag gid: 'V-223448'
  tag rid: 'SV-223448r533198_rule'
  tag stig_id: 'ACF2-ES-000270'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25109r504477_fix'
  tag satisfies: ['SRG-OS-000080-GPOS-00048', 'SRG-OS-000259-GPOS-00100', 'SRG-OS-000324-GPOS-00125']
  tag 'documentable'
  tag legacy: ['V-97593', 'SV-106697']
  tag cci: ['CCI-000213', 'CCI-001499', 'CCI-002235']
  tag nist: ['AC-3', 'CM-5 (6)', 'AC-6 (10)']
end
