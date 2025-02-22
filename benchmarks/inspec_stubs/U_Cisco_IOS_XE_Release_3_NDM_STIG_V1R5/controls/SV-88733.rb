control 'SV-88733' do
  title 'If the Cisco IOS XE router uses mandatory access control, the Cisco IOS XE router  must enforce organization-defined mandatory access control policies over all subjects and objects.'
  desc 'Mandatory access control policies constrain what actions subjects can take with information obtained from data objects for which they have already been granted access, thus preventing the subjects from passing the information to unauthorized subjects and objects. This class of mandatory access control policies also constrains what actions subjects can take with respect to the propagation of access control privileges; that is, a subject with a privilege cannot pass that privilege to other subjects.

Enforcement of mandatory access control is typically provided via an implementation that meets the reference monitor concept. The reference monitor enforces (mediates) access relationships between all subjects and objects based on privilege and need to know.

The mandatory access control policies are defined uniquely for each network device, so they cannot be specified in the requirement. An example of where mandatory access control may be needed is to prevent administrators from tampering with audit objects.'
  desc 'check', 'Verify that the Cisco IOS XE router is configured with different privilege levels for different users.

The configuration should look like the example below:

username USER1 privilege 7 password 7 08751D6D000A061843595F
username USER2 privilege 15 password 7 06525E02455D0A16544541

If different privilege levels are not defined, this is a finding.'
  desc 'fix', 'Configure the Cisco IOS XE router with different privilege levels for different users.

The configuration should look similar to the example below:

username USER1 privilege 7 password 7 08751D6D000A061843595F
username USER2 privilege 15 password 7 06525E02455D0A16544541'
  impact 0.5
  ref 'DPMS Target Cisco IOS XE NDM'
  tag check_id: 'C-74149r3_chk'
  tag severity: 'medium'
  tag gid: 'V-74059'
  tag rid: 'SV-88733r2_rule'
  tag stig_id: 'CISR-ND-000120'
  tag gtitle: 'SRG-APP-000491-NDM-000316'
  tag fix_id: 'F-80601r3_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-003014']
  tag nist: ['CM-6 b', 'AC-3 (3)']
end
