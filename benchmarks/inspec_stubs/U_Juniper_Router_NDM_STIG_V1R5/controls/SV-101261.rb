control 'SV-101261' do
  title 'The Juniper router must be configured to prohibit installation of software without explicit privileged status.'
  desc 'Allowing anyone to install software, without explicit privileges, creates the risk that untested or potentially malicious software will be installed on the system.  This requirement applies to code changes and upgrades for all network devices.'
  desc 'check', 'Review the router configuration to verify that it is compliant with this requirement. The configuration example below depicts a class JR_ENGINEER that is not permitted to add or change software installed on the router.

login {
    class JR_ENGINEER {
        permissions all;
        deny-commands "request system software";
    }

Note: The following are the options under request system software:
  abort         -Abort software upgrade
  add            -Add extension or upgrade package
  delete      -Remove extension or upgrade package
  rollback   -Roll back to previous set of packages
  validate   -Verify package compatibility with current configuration

If the router is not configured to prohibit installation of software without explicit privileged status, this is a finding.'
  desc 'fix', 'Configure one or more classes as shown in the example below whose users will not be permitted to add or change software installed on the router.

[edit system]
set login class JR_ENGINEER permissions all 
set login class JR_ENGINEER deny-commands “(request system software)”

Note: The predefined classes operator and Read-only do not have permissions to install software.'
  impact 0.5
  ref 'DPMS Target Juniper Router NDM'
  tag check_id: 'C-90315r2_chk'
  tag severity: 'medium'
  tag gid: 'V-91161'
  tag rid: 'SV-101261r1_rule'
  tag stig_id: 'JUNI-ND-001060'
  tag gtitle: 'SRG-APP-000378-NDM-000302'
  tag fix_id: 'F-97359r3_fix'
  tag 'documentable'
  tag cci: ['CCI-001812']
  tag nist: ['CM-11 (2)']
end
