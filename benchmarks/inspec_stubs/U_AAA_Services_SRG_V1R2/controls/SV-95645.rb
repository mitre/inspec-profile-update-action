control 'SV-95645' do
  title 'AAA Services must not be configured with shared accounts.'
  desc 'Shared accounts configured for use on a network device do not allow for accountability or repudiation of individuals using them. If shared accounts are not changed when someone leaves the group, that person could possibly gain control of the network device. Having shared accounts does not allow for proper auditing of who is accessing or changing the network. For this reason, shared accounts are not permitted.'
  desc 'check', 'If AAA Services rely on directory services for user account management, this is not applicable and the connected directory services must perform this function.

Verify AAA Services are not configured with shared accounts. Identify group profile definitions that do not meet the accounts user-id naming convention. 

Below is a super-user example of how an SA profile may be associated.

Group Profile Information
group = super-user{
profile_id = 40
profile_cycle = 1
service=shell {
default cmd=permit
cmd=debug {
deny all
permit .*
}
}
}

Below is an example of the user definition that should be assigned with a valid ID (not rtr-geek). Look for group accounts here:

user = rtr-geek{
profile_id = 45
profile_cycle = 1
member = rtr_super
password = des "********"
}

If AAA Services are configured with shared accounts (group profiles), this is a finding.'
  desc 'fix', 'Configure AAA Services with no shared accounts. Remove all group profiles.'
  impact 0.5
  ref 'DPMS Target SRG-APP-AAA'
  tag check_id: 'C-80673r1_chk'
  tag severity: 'medium'
  tag gid: 'V-80935'
  tag rid: 'SV-95645r1_rule'
  tag stig_id: 'SRG-APP-000516-AAA-000620'
  tag gtitle: 'SRG-APP-000516-AAA-000620'
  tag fix_id: 'F-87791r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
