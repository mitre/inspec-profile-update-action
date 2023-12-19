control 'SV-22074' do
  title 'Site WMAN systems must implement strong authentication from the user or WMAN subscriber device to WMAN network.'
  desc 'Broadband systems not compliant with authentication requirements could allow a hacker to gain
access to the DoD network.'
  desc 'check', 'Detailed Policy Requirements:

The IAO has not ensured that site WMAN systems implement strong authentication from the User or WMAN subscriber device to WMAN network.

-For tactical or commercial WMAN systems operated in a non-tactical environment: User ID and
password or shared secret authentication shall be implemented between the User or WMAN
subscriber device to the WMAN network. When user ID and password are used, the complexity requirements of the password must be compliant with JTF-GNO CTO 07-15Rev1:
 --Password complexity is a case sensitive mixture of upper case letters, lower case letters, special characters, and numbers, including at least one of each.

Check Procedures:

 - For non-tactical WMAN systems, verify the system uses either User ID and password or shared secret authentication between the User or WMAN subscriber device (respectively) to the WMAN network. 

If User ID and password is used, verify the password meets the complexity requirements of CTO 07-15Rev1. Have the system administrator show the password complexity settings in the management console of the WMAN access point.  Mark as a finding if the requirements are not met.'
  desc 'fix', 'Comply with requirement.'
  impact 0.5
  ref 'DPMS Target Wireless Client'
  tag check_id: 'C-25554r1_chk'
  tag severity: 'medium'
  tag gid: 'V-19904'
  tag rid: 'SV-22074r1_rule'
  tag stig_id: 'WIR0315-03'
  tag gtitle: 'WMAN authentication - Subscriber to Network'
  tag fix_id: 'F-20573r6_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag ia_controls: 'ECSC-1, ECWN-1'
end
