control 'SV-223721' do
  title 'The IBM RACF Automatic Data Set Protection (ADSP) SETROPTS value must be set to NOADSP.'
  desc 'To assure accountability and prevent unauthenticated access, organizational users must be identified and authenticated to prevent potential misuse and compromise of the system.

Organizational users include organizational employees or individuals the organization deems to have equivalent status of employees (e.g., contractors). Organizational users (and processes acting on behalf of users) must be uniquely identified and authenticated to all accesses, except for the following: 

1) Accesses explicitly identified and documented by the organization. Organizations document specific user actions that can be performed on the information system without identification or authentication; and

2) Accesses that occur through authorized use of group authenticators without individual authentication. Organizations may require unique identification of individuals in group accounts (e.g., shared privilege accounts) or for detailed accountability of individual activity.'
  desc 'check', 'From the ISPF Command Shell enter:
SETROPTS LIST

If the ADSP value is NOT IN EFFECT, this is not a finding.

Note: NOADSP is the required setting. In the SETROPTS LIST output this will display as AUTOMATIC DATASET PROTECTION IS NOT IN EFFECT.

If the ADSP value is IN EFFECT, this is a finding.'
  desc 'fix', 'Configure ADSP SETROPTS value to be set to NOADSP.

Evaluate the impact associated with implementation of the control option. Develop a plan of action to implement the control option as specified in the example below:

NOADSP is set with the command SETR NOADSP.'
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25394r514851_chk'
  tag severity: 'medium'
  tag gid: 'V-223721'
  tag rid: 'SV-223721r604139_rule'
  tag stig_id: 'RACF-ES-000740'
  tag gtitle: 'SRG-OS-000104-GPOS-00051'
  tag fix_id: 'F-25382r514852_fix'
  tag 'documentable'
  tag legacy: ['V-98149', 'SV-107253']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
