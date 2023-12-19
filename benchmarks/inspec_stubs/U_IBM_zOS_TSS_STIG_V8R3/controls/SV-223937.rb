control 'SV-223937' do
  title 'The number of CA-TSS control ACIDs must be justified and properly assigned.'
  desc 'Configuring the operating system to implement organization-wide security implementation guides and security checklists ensures compliance with federal standards and establishes a common security baseline across DoD that reflects the most restrictive security posture consistent with operational requirements.

Configuration settings are the set of parameters that can be changed in hardware, software, or firmware components of the system that affect the security posture and/or functionality of the system. Security-related parameters are those parameters impacting the security state of the system, including the parameters required to satisfy other security control requirements. Security-related parameters include, for example: registry settings; account, file, directory permission settings; and settings for functions, ports, protocols, services, and remote connections.'
  desc 'check', 'From the ISPF Command Shell enter:
TSS LIST(ACIDS) TYPE(SCA) DATA(BASIC)

If the persons listed agree with the site security plan this is not a finding.'
  desc 'fix', 'Review all security administrator ACIDs. Evaluate the impact of correcting the deficiency. Develop a plan of action and reduce the number of control ACIDs if not justified. Use information below as guidance.

TYPE=CENTRAL, TYPE=MASTER or also known as "SCA" and "MSCA" level of ACIDS will adhere to the following restrictions based upon documented role/function an individual performs:

-Domain level Information System Security Officer (ISSO) – full administrative authorities and access rights needed to perform required and documented role/responsibilities/function.
-Assistance Domain Level Information System Security Officer or "backup" or ISSO (up to same access as 1).
-DISA SRR Auditor, DoD IG Auditor, SAS70 Auditor – only "view" administrative authorities must be granted and only for those roles/functions that have been formally documented as DISA, DoD IG or SAS70 Auditors and approved by the DISA AO for those position/functions/roles. 

Exception: Until scoping is worked out and resolved, DISA OST team members may be defined as TYPE=CENTRAL with limited authority such as ACID(INFO,MAINTAIN). All OST Team member ACIDS will be changed to TYPE=LIMITED and scoped accordingly to allow password resets upon verification of users, yet to limit and eliminate any potential risk associated with resetting of MSCA or other SCA level accounts. NO Other exceptions will exist.'
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25610r516210_chk'
  tag severity: 'medium'
  tag gid: 'V-223937'
  tag rid: 'SV-223937r561402_rule'
  tag stig_id: 'TSS0-ES-000640'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-25598r516211_fix'
  tag 'documentable'
  tag legacy: ['SV-107685', 'V-98581']
  tag cci: ['CCI-000366', 'CCI-002145']
  tag nist: ['CM-6 b', 'AC-2 (11)']
end
