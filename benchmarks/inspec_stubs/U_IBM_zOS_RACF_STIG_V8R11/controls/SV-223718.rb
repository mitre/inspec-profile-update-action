control 'SV-223718' do
  title 'IBM interactive USERIDs defined to RACF must have the required fields completed.'
  desc 'Interactive users are considered to be users of CICS, IMS, TSO/E, NetView, or other products that support logging on at a terminal. Improper assignments of attributes in the LOGONID record for interactive users may allow users excessive privileges resulting in unauthorized access.'
  desc 'check', 'From a z/OS command screen enter:
ListUser *

Examine each user entry that has either TSO, CICS, ROSCOE, IMS, or any other products that support logging on at a terminal. 

If every user is fully identified with all of the following condition, this is not a finding.

-Each interactive userid has a valid LAST-ACCESS date that does not contain the value UNKNOWN.
-Each interactive userid has PASS-INTERVAL define and set to a value of 60 days.

Note: FTP only process and server to server userids may have PASSWORD(NOINTERVAL) specified. These users must be identified in the FTPUSERS group in the Dialog Process or FTP in the name field. Additionally these users must change their passwords on an annual basis.'
  desc 'fix', 'Review all interactive USERID definitions to ensure required information is provided. Evaluate the impact of correcting any deficiencies. Develop a plan of action and implement the required changes.

The PASSWORD-INTERVAL for an interactive user must be set to 60 days.

Note: FTP only process and server to server userids may have PASSWORD(NOINTERVAL) specified. These users must be identified in the FTPUSERS group in the Dialog Process or FTP in the name field. Additionally, these users must change their passwords on an annual basis or less.

A sample command to accomplish this is shown here:
PW USER(<userid>) INTERVAL(60).

The LAST-ACCESS date must be set to a valid date and not to the value UNKNOWN. A sample command to accomplish this is shown here:
ALU <userid> RESUME'
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25391r514842_chk'
  tag severity: 'medium'
  tag gid: 'V-223718'
  tag rid: 'SV-223718r604139_rule'
  tag stig_id: 'RACF-ES-000710'
  tag gtitle: 'SRG-OS-000104-GPOS-00051'
  tag fix_id: 'F-25379r514843_fix'
  tag 'documentable'
  tag legacy: ['V-98143', 'SV-107247']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
