control 'SV-223717' do
  title 'IBM RACF users must have the required default fields.'
  desc "Ensure that Every USERID is uniquely identified to the system. Within the USERID record, the user's name, default group, the owner, and the user's passdate or phrasedate fields are completed. This will uniquely identify each user. If these fields are not completed for each user, user accountability will become lost.

RACF will automatically assign the default group as the password if a password is not explicitly coded. Assign a unique password to every userid to prevent unauthorized access by a person who knows the default group for a new userid."
  desc 'check', 'From a z/OS command screen enter:
ListUser *

Examine each user entry verify every user is fully identified with all of the following conditions:
-A completed NAME field that can either be traced back to a current DD2875 or a Vendor Requirement (example: A Started Task). 
-The presence of the DEFAULT-GROUP and OWNER fields. 
-The PASSDATE field or the PHRASEDATE field accordingly is not set to N/A excluding users with the PROTECTED attribute. 

If all of the above are true, this is not a finding. 

If any of above is untrue, this is a finding.'
  desc 'fix', "Review all USERID definitions to ensure required information is provided. Evaluate the impact of correcting the deficiency. Develop a plan of action and implement the changes listed in this PDI. The following are sample commands to correct this vulnerability.

-To Add a NAME to a userid with the command ALU <userid> NAME('lastname, firstname').
-Every user will be assigned a default group by default. A sample command to reassign a default group is shown here: ALU <userid> DFLTGRP(<newdefaultgroup>). You must first be connected to a group via the RACF CONNECT command before making it a default group.
-A PASSDATE field or a PHRASEDATE field showing 00.000 indicates that a temporary password or password phrase has been assigned but the user has not logged in and set a permanent value. This could indicate that a new userid was recently added or that a userid previously added is unused and should be considered for deletion. The ISSO should investigate and determine if the userid should be deleted or that the new user should be contacted and told to login to set a permanent value."
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25390r514839_chk'
  tag severity: 'medium'
  tag gid: 'V-223717'
  tag rid: 'SV-223717r604139_rule'
  tag stig_id: 'RACF-ES-000700'
  tag gtitle: 'SRG-OS-000104-GPOS-00051'
  tag fix_id: 'F-25378r514840_fix'
  tag 'documentable'
  tag legacy: ['SV-107245', 'V-98141']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
