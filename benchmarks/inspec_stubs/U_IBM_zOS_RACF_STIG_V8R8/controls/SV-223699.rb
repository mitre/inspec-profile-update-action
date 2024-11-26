control 'SV-223699' do
  title 'The IBM RACF SETROPTS SAUDIT value must be specified.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', 'From the ISPF Command Shell enter:
SETROPTS LIST

If the SAUDIT value is listed as one of the ATTRIBUTES, this is not a finding.

If the NOSAUDIT value is listed as one of the ATTRIBUTES, this is a finding.'
  desc 'fix', 'Evaluate the impact associated with implementation of the control option. Develop a plan of action to implement the control option as specified in the example below:

Note: that in order to set or list the SAUDIT value, the RACF AUDITOR attribute is required. Reference the documentation for the SETROPTS command in the RACF Command Language Reference. 

The RACF Command SETR LIST will show the status of RACF Controls including the value for SAUDIT. 

SAUDIT is activated and set to the required value by issuing the command SETR SAUDIT.'
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25372r514785_chk'
  tag severity: 'medium'
  tag gid: 'V-223699'
  tag rid: 'SV-223699r604139_rule'
  tag stig_id: 'RACF-ES-000520'
  tag gtitle: 'SRG-OS-000468-GPOS-00212'
  tag fix_id: 'F-25360r514786_fix'
  tag 'documentable'
  tag legacy: ['V-98105', 'SV-107209']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
