control 'SV-245775' do
  title 'Information Assurance - System Access Control Records (DD Form 2875 or equivalent)'
  desc 'If accurate records of authorized users are not maintained, then unauthorized personnel could have access to the system. Failure to have user sign an agreement may preclude disciplinary actions if user does not comply with security procedures

REFERENCES:

CJCSI 6510.01F, INFORMATION ASSURANCE (IA) AND SUPPORT TO COMPUTER NETWORK DEFENSE (CND), Encl C, para 26.a.

DoDI 8500.01, SUBJECT: Cybersecurity, March 14, 2014 , Encl 2, para 13.j., 13.y.(1); Encl 3, para 10.c., 18.b., 19.c.

NIST Special Publication 800-53 (SP 800-53), Rev 4, Controls: AC-3(3), AC-3(4), AC-3(5), AC-3(7), AC-2(7).                

DoD 8570.01-M, Information Assurance Workforce Improvement Program'
  desc 'check', '1. Check to ensure there are written procedures for personnel who request access to a computer system. 

2. Note in the report finding details what access form is used (locally developed, Service level or DD Form 2875).

3. If applicable - ensure the most current version of the DD Form 2875, System Authorization Access Request (SAAR) is being used. 

4. Note what training is required/conducted before system access is granted. 

5. Review a sample of system access request forms to ensure the forms contain appropriate information for checking compliance with security requirements for privileged, user, classified and unclassified systems access.  Information required will include identification of the individual requesting access, signature dates, supervisory approval, ISSM and SM approval, investigation level and security clearance required, investigation and security clearance possessed, IA (AKA: ADP) position level and date Information Assurance Training was completed. 

6. Check to ensure a separate "User Agreement" also exists for both system "users" and for "privileged account holders" (System Administrators...). For privileged users a signed Privileged Access Statement IAW Appendix 4 of DoD 8570.01-M, Information Assurance Workforce Improvement Program is required.

7. In a tactical environment the forms used to control systems access might not be readily accessible in the field. Determine where the forms are maintained and if the location is not within reach, attempt to obtain a sample copy of a completed form via fax, email, etc. Fixed locations with IA staff assigned should have the forms available.'
  desc 'fix', '1. Written procedures for personnel who request access to a computer system must be developed. 

2. A System Authorization Access Request (SAAR) form (DD Form 2875 or equivalent) must be used to define and control individual access for systems. If applicable, the most current version of the DD Form 2875, SAAR must be used. Locally developed or Service level forms may also be used if the same information found on the DD Form 2875 is used.

3. Local or Service level System Authorization Access Request (SAAR) forms must minimally contain appropriate information for checking compliance with security requirements for privileged, routine user, classified and unclassified systems access like on the DD Form 2875.  Information required includes identification of the individual requesting access, signature dates, supervisory approval, ISSM and SM approval, investigation level and security clearance required, investigation and security clearance possessed, IA (AKA: ADP) position level and date Information Assurance Training was completed. 

4. A separate "User Agreement" must be signed by each user before access is granted. This includes both system "users" and "privileged account holders" (System Administrators...). For privileged users a signed Privileged Access Statement IAW Appendix 4 of DoD 8570.01-M, Information Assurance Workforce Improvement Program is required.'
  impact 0.5
  ref 'DPMS Target Traditional Security Checklist'
  tag check_id: 'C-49206r769985_chk'
  tag severity: 'medium'
  tag gid: 'V-245775'
  tag rid: 'SV-245775r769987_rule'
  tag stig_id: 'IA-05.02.01'
  tag gtitle: 'IA-05.02.01'
  tag fix_id: 'F-49161r769986_fix'
  tag 'documentable'
  tag legacy: ['V-31011', 'SV-41058r3_rule']
end
