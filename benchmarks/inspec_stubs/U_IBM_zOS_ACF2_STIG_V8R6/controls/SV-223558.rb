control 'SV-223558' do
  title 'IBM z/OS Emergency LOGONIDs must be properly defined.'
  desc 'Activity under unusual conditions can indicate hostile activity. For example, what is normal activity during business hours can indicate hostile activity if it occurs during off hours.

Depending on mission needs and conditions, account usage restrictions based on conditions and circumstances may be critical to limit access to resources and data to comply with operational or mission access control requirements. Thus, the operating system must be configured to enforce the specific conditions or circumstances under which organization-defined accounts can be used (e.g., by restricting usage to certain days of the week, time of day, or specific durations of time).'
  desc 'check', 'Ask the system administrator to provide a list of all emergency logonids available to the site along with the associated function of each.
If there are no emergency logonids defined, ask the system administrator for an alternate documented procedure to handle emergencies. If there are no emergency logonids and no documented emergency procedure, this is a finding.

If emergency logonids exist, at a minimum, a logonid will exist with the security administration attributes specified in accordance with the following requirements:

For emergency IDs with security administration privileges, but which cannot access and update system data sets:

ACCOUNT

JCL
JOB
MONITOR
NONON CNCL
RULEVLD
RSRCVLD
SECURITY
TSO
TSOPROC(xxxxxxxx)
TSOACCT(none)

An additional class of logonids can exist to perform all operating system functions except ESM administration.

These emergency logonid/logonid(s) will have ability to access and update all system data sets, but will not have security administration privileges. See the following requirements:

JCL
JOB
MONITOR
NON CNCL (Will force logging of all activity.)
TSO
TSOPROC(xxxxxxxx)
TSOACCT(none)

All emergency logonid/logonid(s) are to be implemented with logging to provide an audit trail of their activities.

All emergency logonid/logonid(s) are to be maintained in both the ESM and SYS1.UADS to ensure they are available in the event that the ESM is not functional.

All emergency logonid/logonid(s) will have distinct, different passwords in SYS1.UADS and in the ESM, and the site is to establish procedures to ensure that the passwords differ. The password for any ID in SYS1.UADS is never to match the password for the same ID in the ESM.

All emergency logonid/logonid(s) will have documented procedures to provide a mechanism for the use of the IDs. Their release for use is to be logged, and the log is to be maintained by the ISSO. When an emergency logonid is released for use, its password is to be reset by the ISSO within 12 hours.

If all the emergency logonid items above are true, this is not a finding.

If any item above is untrue, this is a finding.'
  desc 'fix', 'Ensure that Emergency Logonids use these fields to enforce restrictions for Emergency logonids. 

Two classes of emergency logonids may exist. The following privileges and specifications will be used for these logonids:

Note: Only the emergency logonid with the security administration logonid attributes is required.

(1) For emergency IDs with the ability to access and update all system data sets, but which do not have security administration privileges:

NOFSRETAIN
JCL
JOB
MONITOR
NON CNCL (Will force logging of all activity.)
TSO
TSOPROC(xxxxxxxx)
TSOACCT(none)

Example:

SET LID
INSERT logonid NOFSRETAIN JCL JOB MONITOR NON-CNCL TSO TSOPRC(xxxxxxxx) TSOACCT(none)

(2) For emergency IDs with security administration privileges, but which cannot access and update system data sets:

ACCOUNT
NOFSRETAIN
JCL
JOB
MONITOR
NONON CNCL
RULEVLD
RSRCVLD
SECURITY
TSO
TSOPROC(xxxxxxxx)
TSOACCT(none)

Example:

SET LID
INSERT logonid ACCOUNT NOFSRETAIN JCL JOB MONITOR RULEVLD RSRCVLD NONON-CNCL SECURITY TSO TSOPRC(xxxxxxxx) TSOACCT(none)   

If no emergency logonids are in use on the system, develop and document a procedure to manage emergencies access to the system.'
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25231r803624_chk'
  tag severity: 'medium'
  tag gid: 'V-223558'
  tag rid: 'SV-223558r803626_rule'
  tag stig_id: 'ACF2-OS-000220'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-25219r803625_fix'
  tag 'documentable'
  tag legacy: ['V-97821', 'SV-106925']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
