control 'SV-223626' do
  title 'IBM z/OS UNIX MVS data sets used as step libraries in /etc/steplib must be properly protected.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

Access control policies include: identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include: access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system.

'
  desc 'check', 'Refer to the STEPLIBLIST statement in the BPXPRMxx member of PARMLIB. 
If the STEPLIBLIST points to an etc/steplib go to the ISPF Command Shell enter:
OMVS
cd /etc
cat <filename>

If the ESM data set rules for libraries specified in the STEPLIBLIST file do not restrict UPDATE and/or ALTER/ALLOCATE access to only systems programming personnel, this is a finding.

If the ESM data set rules for libraries specified in the STEPLIBLIST file do not specify that all (i.e., failures and successes) UPDATE and/or ALTER/ALLOCATE access will be logged this is a finding.'
  desc 'fix', 'Define the STEPLIBLIST with update and allocate access to libraries residing in the /etc/steplib limited to system programmers only.

The STEPLIBLIST parameter specifies the pathname of the HFS file that contains the list of MVS data sets that are used as step libraries for programs that have the set-user-id or set group id permission bit set. The use of STEPLIBLIST is at the site’s discretion, but if used the value of STEPLIBLIST will be /etc/steplib. All update and alter access to the MVS data sets in the list will be logged and only systems programming personnel will be authorized to update the data sets.'
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25299r504836_chk'
  tag severity: 'medium'
  tag gid: 'V-223626'
  tag rid: 'SV-223626r533198_rule'
  tag stig_id: 'ACF2-US-000110'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25287r504837_fix'
  tag satisfies: ['SRG-OS-000080-GPOS-00048', 'SRG-OS-000259-GPOS-00100', 'SRG-OS-000324-GPOS-00125']
  tag 'documentable'
  tag legacy: ['SV-107061', 'V-97957']
  tag cci: ['CCI-000213', 'CCI-001499', 'CCI-002235']
  tag nist: ['AC-3', 'CM-5 (6)', 'AC-6 (10)']
end
