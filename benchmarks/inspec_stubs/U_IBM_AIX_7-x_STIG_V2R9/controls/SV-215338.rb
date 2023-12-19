control 'SV-215338' do
  title 'AIX system must restrict the ability to switch to the root user to members of a defined group.'
  desc 'Configuring a supplemental group for users permitted to switch to the root user prevents unauthorized users from accessing the root account, even with knowledge of the root credentials.'
  desc 'check', 'Examine the "sugroups" of the root user. Generally only users in the adm group should have su to root capacity.

Run the following command: 

# lsuser -a sugroups root 
root sugroups=system,staff,security

If "sugroups" is blank or "ALL", this is a finding.'
  desc 'fix', 'Use the "chsec" command to only allow users in the adm group to su to root:

# chsec -f /etc/security/user -s root -a sugroups=adm'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16536r294465_chk'
  tag severity: 'medium'
  tag gid: 'V-215338'
  tag rid: 'SV-215338r508663_rule'
  tag stig_id: 'AIX7-00-003030'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-16534r294466_fix'
  tag 'documentable'
  tag legacy: ['SV-101679', 'V-91581']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
