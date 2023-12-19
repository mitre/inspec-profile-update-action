control 'SV-6752' do
  title 'Individual user accounts with passwords are not set up and maintained for the SAN fabric switch.'
  desc 'Without identification and authentication unauthorized users could reconfigure the SAN or disrupt its operation by logging in to the fabric switch and executing unauthorized commands.
The IAO/NSO will ensure individual user accounts with passwords are set up and maintained for the SAN fabric switch in accordance with the guidance contained in Appendix B, CJCSM and the Network Infrastructure STIG.'
  desc 'check', 'The reviewer, with the assistance of the IAO/NSO, will verify that individual user accounts with passwords are set up and maintained for the SAN fabric switch.'
  desc 'fix', 'Develop a plan to reconfigure the SAN fabric switch to require user accounts and passwords.  This plan also needs to include the creation and distribution of user accounts and passwords for each administrator who requires access to the SAN fabric switch.  Obtain CM approval of the plan and then implement the plan.'
  impact 0.5
  ref 'DPMS Target SANS Storage Device'
  ref 'DPMS Target SANS Switch'
  tag check_id: 'C-2486r1_chk'
  tag severity: 'medium'
  tag gid: 'V-6632'
  tag rid: 'SV-6752r1_rule'
  tag stig_id: 'SAN04.009.00'
  tag gtitle: 'SAN Fabric Switch User Accounts with Passwords'
  tag fix_id: 'F-6220r1_fix'
  tag 'documentable'
  tag potential_impacts: 'The IAO/NSO will ensure that individual user accounts with passwords are set up and maintained in accordance with the guidance contained in Appendix B, Chairman Of The Joint Chiefs of Staff Manual CJCSM 6510.1 and the DODI 8500.2.'
  tag responsibility: ['Information Assurance Officer', 'Network Security Officer']
  tag ia_controls: 'IAIA-1, IAIA-2'
end
