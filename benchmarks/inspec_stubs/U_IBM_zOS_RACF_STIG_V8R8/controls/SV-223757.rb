control 'SV-223757' do
  title 'IBM z/OS must configure system wait times to protect resource availability based on site priorities.'
  desc "Automatic session termination addresses the termination of user-initiated logical sessions in contrast to the termination of network connections that are associated with communications sessions (i.e., network disconnect). A logical session (for local, network, and remote access) is initiated whenever a user (or process acting on behalf of a user) accesses an organizational information system. Such user sessions can be terminated (and thus terminate user access) without terminating network sessions.

Session termination terminates all processes associated with a user's logical session except those processes that are specifically created by the user (i.e., session owner) to continue after the session is terminated.

Conditions or trigger events requiring automatic session termination can include, for example, organization-defined periods of user inactivity, targeted responses to certain types of incidents, and time-of-day restrictions on information system use.

This capability is typically reserved for specific operating system functionality where the system owner, data owner, or organization requires additional assurance."
  desc 'check', 'Refer to IEASYS00 member in SYS1.PARMLIB Concatenation. Determine proper SMFPRMxx member. 

Examine the JWT, SWT, and TWT values.

If the JWT parameter is greater than "15" minutes, and the system is processing unclassified information, review the following items. 

If any of these items is true, this is not a finding.

-If a session is not terminated, but instead is locked out after "15" minutes of inactivity, a process must be in place that requires user identification and authentication before the session is unlocked. Session lock-out will be implemented through system controls or terminal screen protections.

-A system’s default time for terminal lock-out or session termination may be lengthened to "30" minutes at the discretion of the ISSM or ISSO. The ISSA and/or ISSO will maintain the documentation for each system with a time-out adjusted beyond the 15-minute recommendation to explain the basis for this decision.

-The ISSM and/or ISSO may set selected userids to have a time-out of up to "60" minutes in order to complete critical reports or transactions without timing out. Each exception must meet the following criteria:
 -The time-out exception cannot exceed "60" minutes.
 -A letter of justification fully documenting the user requirement(s) must be submitted and approved by the site ISSM or ISSO. In addition, this letter must identify an alternate means of access control for the terminal(s) involved (e.g., a room that is locked at all times, a room with a cipher lock to limit access, a password protected screen saver set to "30" minutes or less, etc.).
 -The requirement must be revalidated on an annual basis.

If the TWT and SWT values are equal or less than the JWT value, this is not a finding.'
  desc 'fix', 'Configure the SMFPRMxx JWT to "15" minutes for classified systems.

The JWT parameter can be greater than "15" minutes if the system is processing unclassified information and the following items are reviewed:
-If a session is not terminated, but instead is locked out after "15" minutes of inactivity, a process must be in place that requires user identification and authentication before the session is unlocked. Session lock-out will be implemented through system controls or terminal screen protections.

-A system’s default time for terminal lock-out or session termination may be lengthened to "30" minutes at the discretion of the ISSM or ISSO. The ISSM and/or ISSO will maintain the documentation for each system with a time-out adjusted beyond the 15-minute recommendation to explain the basis for this decision.

-The ISSM and/or ISSO may set selected userids to have a time-out of up to "60" minutes in order to complete critical reports or transactions without timing out. Each exception must meet the following criteria:
 -The time-out exception cannot exceed 60 minutes.
 -A letter of justification fully documenting the user requirement(s) must be submitted and approved by the site ISSM or ISSO. In addition, this letter must identify an alternate means of access control for the terminal(s) involved (e.g., a room that is locked at all times, a room with a cipher lock to limit access, a password protected screen saver set to 30 minutes or less, etc.).
 -The requirement must be revalidated on an annual basis.

Configure any TWT and or SWT to be equal or less than the JWT.'
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25430r514959_chk'
  tag severity: 'medium'
  tag gid: 'V-223757'
  tag rid: 'SV-223757r853609_rule'
  tag stig_id: 'RACF-OS-000010'
  tag gtitle: 'SRG-OS-000279-GPOS-00109'
  tag fix_id: 'F-25418r514960_fix'
  tag 'documentable'
  tag legacy: ['SV-107325', 'V-98221']
  tag cci: ['CCI-002361']
  tag nist: ['AC-12']
end
