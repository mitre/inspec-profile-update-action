control 'SV-22073' do
  title 'Site WMAN systems must implement strong authentication from the user or WMAN subscriber device to WMAN network.'
  desc 'Broadband systems not compliant with authentication requirements could allow a hacker to gain
access to the DoD network.'
  desc 'check', 'Detailed Policy Requirements:

The site WMAN systems must implement strong authentication from the User or WMAN subscriber device to WMAN network.

-For tactical or commercial WMAN systems operated in a non-tactical environment: User ID and password or shared secret authentication shall be implemented between the user or WMAN subscriber device to the WMAN network. When user ID/Password are used, the length requirements of the password must be compliant with JTF-GNO CTO 07-15Rev1:
o 15 character password length (or the maximum length supported by the system if a 15 character password is not supported).

Check Procedures:

For non-tactical WMAN systems, verify the system uses either User ID and password or shared secret authentication between the User or WMAN subscriber device (respectively) to the WMAN network. If User ID and password is used, verify the password meets the length requirements of CTO 07-15Rev1.

Mark as a finding if the password length requirements are not met.'
  desc 'fix', 'Comply with requirement.'
  impact 0.5
  ref 'DPMS Target Wireless Client'
  tag check_id: 'C-25553r1_chk'
  tag severity: 'medium'
  tag gid: 'V-19903'
  tag rid: 'SV-22073r1_rule'
  tag stig_id: 'WIR0315-02'
  tag gtitle: 'WMAN authentication - Subscriber to Network'
  tag fix_id: 'F-20573r6_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag ia_controls: 'ECSC-1, ECWN-1'
end
