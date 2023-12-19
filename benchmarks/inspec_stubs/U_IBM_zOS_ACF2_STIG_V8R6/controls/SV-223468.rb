control 'SV-223468' do
  title 'The CA-ACF2 LOGONID with the REFRESH attribute must have procedures for utilization.'
  desc 'Configuring the operating system to implement organization-wide security implementation guides and security checklists ensures compliance with federal standards and establishes a common security baseline across DoD that reflects the most restrictive security posture consistent with operational requirements.'
  desc 'check', 'From the ACF Command screen enter:
SET LID 
LIST IF(REFRESH)

If procedures exist to utilize the logonid with the REFRESH attribute to refresh ACF2 global options, this is not a finding.

Example:
When the ISSO determines it necessary to refresh the ACF2 global options, the ISSO will do the following:

-Activate the REFRESH ID with the following setting(s):
NOSUSPEND
NOPSWD EXP
PASSWORD(new password)

-Instruct Operations to perform the REFRESH.

-Deactivate the REFRESH ID with the following setting:
SUSPEND

If no procedures exist in accordance with the STIG requirements to utilize the logonid with the REFRESH attribute to refresh ACF2 global options, this is a finding.'
  desc 'fix', 'Review security procedures for defining LOGONIDs and develop documentation of requirements for the LOGONID associated with the REFRESH attribute. 

Example: 
When the ISSO determines it necessary to refresh the ACF2 global options, the ISSO will do the following:

-Activate the REFRESH ID with the following setting(s):
NOSUSPEND
NOPSWD EXP
PASSWORD(new password)

-Instruct Operations to perform the REFRESH.

-Deactivate the REFRESH ID with the following setting:
SUSPEND'
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25141r504522_chk'
  tag severity: 'medium'
  tag gid: 'V-223468'
  tag rid: 'SV-223468r533198_rule'
  tag stig_id: 'ACF2-ES-000500'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-25129r504523_fix'
  tag 'documentable'
  tag legacy: ['V-97635', 'SV-106739']
  tag cci: ['CCI-000225', 'CCI-000366']
  tag nist: ['AC-6', 'CM-6 b']
end
