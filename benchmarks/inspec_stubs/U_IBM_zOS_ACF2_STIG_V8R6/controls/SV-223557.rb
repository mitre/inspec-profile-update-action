control 'SV-223557' do
  title 'IBM z/OS must configure system waittimes to protect resource availability based on site priorities.'
  desc 'Once an attacker establishes access to a system, the attacker often attempts to create a persistent method of reestablishing access. One way to accomplish this is for the attacker to enable an existing disabled account. Sending notification of account enabling actions to the System Administrator and ISSO is one method for mitigating this risk. Such a capability greatly reduces the risk that operating system accessibility will be negatively affected for extended periods of time and also provides logging that can be used for forensic purposes.

In order to detect and respond to events that affect user accessibility and application processing, operating systems must audit account enabling actions and, as required, notify the appropriate individuals so they can investigate the event.

To address access requirements, many operating systems can be integrated with enterprise-level authentication/access/auditing mechanisms that meet or exceed access control policy requirements.'
  desc 'check', 'Refer to IEASYS00 member in SYS1.PARMLIB Concatenation. Determine proper SMFPRMxx member. 

Examine the JWT; SWT, and TWT values.

If the JWT parameter is greater than "15" minutes, and the system is processing unclassified information, review the following items. 

If any of these items is true, this is not a finding.

If a session is not terminated, but instead is locked out after 15 minutes of inactivity, a process must be in place that requires user identification and authentication before the session is unlocked. Session lock-out will be implemented through system controls or terminal screen protections.

A system’s default time for terminal lock-out or session termination may be lengthened to 30 minutes at the discretion of the ISSM or ISSO. The ISSA and/or ISSO will maintain the documentation for each system with a time-out adjusted beyond the 15-minute recommendation to explain the basis for this decision.

The ISSM and/or ISSO may set selected userids to have a time-out of up to 60 minutes in order to complete critical reports or transactions without timing out. Each exception must meet the following criteria:

The time-out exception cannot exceed 60 minutes. A letter of justification fully documenting the user requirement(s) must be submitted and approved by the site ISSM or ISSO. In addition, this letter must identify an alternate means of access control for the terminal(s) involved (e.g., a room that is locked at all times, a room with a cipher lock to limit access, a password protected screen saver set to 30 minutes or less, etc). The requirement must be revalidated on an annual basis.

If the TWT and SWT values are equal or less than the JWT value, this is not a finding.'
  desc 'fix', 'Configure the SMFPRMxx JWT to "15" minutes for classified systems.

The JWT parameter can be greater than 15 minutes if the system is processing unclassified information and the following items are reviewed.

If a session is not terminated, but instead is locked out after 15 minutes of inactivity, a process must be in place that requires user identification and authentication before the session is unlocked. Session lock-out will be implemented through system controls or terminal screen protections.

A system’s default time for terminal lock-out or session termination may be lengthened to 30 minutes at the discretion of the ISSM or ISSO. The ISSM and/or ISSO will maintain the documentation for each system with a time-out adjusted beyond the 15-minute recommendation to explain the basis for this decision.

The ISSM and/or ISSO may set selected userids to have a time-out of up to 60 minutes in order to complete critical reports or transactions without timing out. Each exception must meet the following criteria:

The time-out exception cannot exceed 60 minutes. A letter of justification fully documenting the user requirement(s) must be submitted and approved by the site ISSM or ISSO. In addition, this letter must identify an alternate means of access control for the terminal(s) involved (e.g., a room that is locked at all times, a room with a cipher lock to limit access, a password protected screen saver set to 30 minutes or less, etc). The requirement must be revalidated on an annual basis.

Configure any TWT and or SWT to be equal or less than the JWT.'
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25230r504698_chk'
  tag severity: 'medium'
  tag gid: 'V-223557'
  tag rid: 'SV-223557r533198_rule'
  tag stig_id: 'ACF2-OS-000210'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-25218r504699_fix'
  tag 'documentable'
  tag legacy: ['V-97819', 'SV-106923']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
