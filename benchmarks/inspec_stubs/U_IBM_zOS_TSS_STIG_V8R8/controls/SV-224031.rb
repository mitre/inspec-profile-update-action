control 'SV-224031' do
  title 'IBM z/OS must configure system wait times to protect resource availability based on site priorities.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.'
  desc 'check', %q(Refer to IEASYS00 member in SYS1.PARMLIB Concatenation. Determine proper SMFPRMxx member. 

Examine the JWT, SWT, and TWT values.

If the JWT parameter is greater than "15" minutes, and the system is processing unclassified information, review the following items. 

If any of these items is true, this is not a finding.

-If a session is not terminated, but instead is locked out after 15 minutes of inactivity, a process must be in place that requires user identification and authentication before the session is unlocked. Session lock-out will be implemented through system controls or terminal screen protections.

-A system's default time for terminal lock-out or session termination may be lengthened to 30 minutes at the discretion of the ISSM or ISSO. The ISSM and/or ISSO will maintain the documentation for each system with a time-out adjusted beyond the 15-minute recommendation to explain the basis for this decision.

-The ISSM and/or ISSO may set selected userids to have a time-out of up to 60 minutes in order to complete critical reports or transactions without timing out. Each exception must meet the following criteria:
 -The time-out exception cannot exceed 60 minutes.
 -A letter of justification fully documenting the user requirement(s) must be submitted and approved by the site ISSM or ISSO. In addition, this letter must identify an alternate means of access control for the terminal(s) involved (e.g., a room that is locked at all times, a room with a cipher lock to limit access, a password protected screen saver set to 30 minutes or less, etc.).
 -The requirement must be revalidated on an annual basis.

If the TWT and SWT values are equal or less than the JWT value, this is not a finding.)
  desc 'fix', %q(Configure the SMFPRMxx JWT to "15" minutes for classified systems.

The JWT parameter can be greater than "15" minutes if the system is processing unclassified information and the following items are reviewed.

-If a session is not terminated, but instead is locked out after "15" minutes of inactivity, a process must be in place that requires user identification and authentication before the session is unlocked. Session lock-out will be implemented through system controls or terminal screen protections.

-A system's default time for terminal lock-out or session termination may be lengthened to "30" minutes at the discretion of the ISSM or ISSO. The ISSM and/or ISSO will maintain the documentation for each system with a time-out adjusted beyond the 15-minute recommendation to explain the basis for this decision.

-The ISSM and/or ISSO may set selected userids to have a time-out of up to "60" minutes in order to complete critical reports or transactions without timing out. Each exception must meet the following criteria:

-The time-out exception cannot exceed "60" minutes.

-A letter of justification fully documenting the user requirement(s) must be submitted and approved by the site ISSM or ISSO. In addition, this letter must identify an alternate means of access control for the terminal(s) involved (e.g., a room that is locked at all times, a room with a cipher lock to limit access, a password protected screen saver set to 30 minutes or less, etc.).

-The requirement must be revalidated on an annual basis.

Configure any TWT and or SWT to be equal or less than the JWT.)
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25704r868996_chk'
  tag severity: 'medium'
  tag gid: 'V-224031'
  tag rid: 'SV-224031r868998_rule'
  tag stig_id: 'TSS0-OS-000350'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-25692r868997_fix'
  tag 'documentable'
  tag legacy: ['SV-107875', 'V-98771']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
