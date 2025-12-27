control 'SV-255957' do
  title 'If the Arista network device uses role-based access control, the network device must enforce organization-defined role-based access control policies over defined subjects and objects.'
  desc 'Organizations can create specific roles based on job functions and the authorizations (i.e., privileges) to perform needed operations on organizational information systems associated with the organization-defined roles. When administrators are assigned to the organizational roles, they inherit the authorizations or privileges defined for those roles. Role-based access control (RBAC) simplifies privilege administration for organizations because privileges are not assigned directly to every administrator (which can be a significant number of individuals for mid- to large-size organizations) but are instead acquired through role assignments. RBAC can be implemented either as a mandatory or discretionary form of access control.

The RBAC policies and the subjects and objects are defined uniquely for each network device, so they cannot be specified in the requirement.

'
  desc 'check', 'Determine if the network device enforces role-based access control policy over defined subjects and objects. This requirement may be met through use of a properly configured authentication server.

Note: If not using role-based access for the network device, this check is Not Applicable.

Step 2: Verify the Arista network device configured AAA servers are synchronized for all role-based authentication access control structure defined by role types and user-defined control policies over defined subjects and objects.

switch(config)#show running-config | section role

role network-admin
   10 permit command .*
!
role operator
   10 permit command show running-config [all|detail] sanitized
   20 deny command >|>>|extension|\\||session|do|delete|copy|rmdir|mkdir|python-shell|bash|platform|scp|append|redirect|tee|more|less|who|show run.*
   30 deny mode config command (no |default )?(username|role|aaa|tcpdump|schedule|event.*)  
   40 permit command .*
!
role tester
   10 permit command show running-config [all|detail] sanitized
   20 deny command >|>>|extension|\\||session|do|delete|copy|rmdir|mkdir|python-shell|bash|platform|scp|append|redirect|tee|more|less|who|show run.*
   30 deny mode config command (no |default )(username|role|aaa|tcpdump|schedule|event.*)
   40 permit command .*

If role-based access control policy is not enforced over defined subjects and objects, this is a finding.'
  desc 'fix', 'Configure the network device and its associated authentication server to enforce role-based access control policy over defined subjects and objects.

switch(config)#
role network-admin
   10 permit command .*
!
role operator
   10 permit command show running-config [all|detail] sanitized
   20 deny command >|>>|extension|\\||session|do|delete|copy|rmdir|mkdir|python-shell|bash|platform|scp|append|redirect|tee|more|less|who|show run.*
   30 deny mode config command (no |default )?(username|role|aaa|tcpdump|schedule|event.*)  
   40 permit command .*
!
role tester
   10 permit command show running-config [all|detail] sanitized
   20 deny command >|>>|extension|\\||session|do|delete|copy|rmdir|mkdir|python-shell|bash|platform|scp|append|redirect|tee|more|less|who|show run.*
   30 deny mode config command (no |default )(username|role|aaa|tcpdump|schedule|event.*)
   40 permit command .*'
  impact 0.5
  ref 'DPMS Target Arista MLS EOS 4.2x NDM'
  tag check_id: 'C-59633r882211_chk'
  tag severity: 'medium'
  tag gid: 'V-255957'
  tag rid: 'SV-255957r882213_rule'
  tag stig_id: 'ARST-ND-000550'
  tag gtitle: 'SRG-APP-000329-NDM-000287'
  tag fix_id: 'F-59576r882212_fix'
  tag satisfies: ['SRG-APP-000329-NDM-000287', 'SRG-APP-000380-NDM-000304']
  tag 'documentable'
  tag cci: ['CCI-001813', 'CCI-002169']
  tag nist: ['CM-5 (1) (a)', 'AC-3 (7)']
end
