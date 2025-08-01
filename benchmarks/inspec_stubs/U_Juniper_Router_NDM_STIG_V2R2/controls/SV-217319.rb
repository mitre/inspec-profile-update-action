control 'SV-217319' do
  title 'The Juniper router must be configured to limit privileges to change the software resident within software libraries.'
  desc 'Changes to any software components of the network device can have significant effects on the overall security of the network. Therefore, only qualified and authorized individuals should be allowed administrative access to the network device for implementing any changes or upgrades. If the network device were to enable non-authorized users to make changes to software libraries, those changes could be implemented without undergoing testing, validation, and approval.'
  desc 'check', 'Review the router configuration to verify that it is compliant with this requirement. The configuration example below depicts a class JR_ENGINEER that is not permitted to add, change, or delete software installed on the router.

login {
    class JR_ENGINEER {
        permissions all;
        deny-commands "request system software";
    }

Note: The following are the options under request system software:

abort    - Abort software upgrade
add      - Add extension or upgrade package
delete   - Remove extension or upgrade package
rollback - Roll back to previous set of packages
validate - Verify package compatibility with current configuration

If the router is not configured to limit privileges to change the software resident within software libraries, this is a finding.'
  desc 'fix', 'Configure one or more classes as shown in the example below whose users will not be permitted to add, change, or delete software installed on the router.

[edit system]
set login class JR_ENGINEER permissions all 
set login class JR_ENGINEER deny-commands “(request system software)”

Note: The predefined classes "operator" and "Read-only" do not have permissions to install or delete software.'
  impact 0.5
  ref 'DPMS Target Juniper Router NDM'
  tag check_id: 'C-18546r296535_chk'
  tag severity: 'medium'
  tag gid: 'V-217319'
  tag rid: 'SV-217319r395850_rule'
  tag stig_id: 'JUNI-ND-000460'
  tag gtitle: 'SRG-APP-000133-NDM-000244'
  tag fix_id: 'F-18544r296536_fix'
  tag 'documentable'
  tag legacy: ['SV-101223', 'V-91123']
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
