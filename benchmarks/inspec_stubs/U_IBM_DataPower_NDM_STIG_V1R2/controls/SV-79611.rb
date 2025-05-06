control 'SV-79611' do
  title 'The DataPower Gateway must automatically terminate a network administrator session after organization-defined conditions or trigger events requiring session disconnect.'
  desc "Automatic session termination addresses the termination of administrator-initiated logical sessions in contrast to the termination of network connections that are associated with communications sessions (i.e., network disconnect). A logical session (for local, network, and remote access) is initiated whenever an administrator (or process acting on behalf of a user) accesses a network device. Such administrator sessions can be terminated (and thus terminate network administrator access) without terminating network sessions. 

Session termination terminates all processes associated with an administrator's logical session except those processes that are specifically created by the administrator (i.e., session owner) to continue after the session is terminated. 

Conditions or trigger events requiring automatic session termination can include, for example, organization-defined periods of user inactivity, targeted responses to certain types of incidents, and time-of-day restrictions on information system use. These conditions will vary across environments and network device types."
  desc 'check', %q(Objects >> Device Management >> Web Management Service >> Idle timeout is set to 900 or less. 

Review the administrator's SSH Client Profile: Objects >> Crypto Configuration >> SSH Client Profile >> "Persistent Idle Timeout" is set to 900 or less. If it is not, this is a finding.)
  desc 'fix', 'For the Web Management service used by an administrator, configure an idle timeout (Objects >> Device Management >> Web Management Service): The time after which to invalidate idle administrator sessions. When invalidated, the web interface requires reauthentication.

For the SSH command-line interface used by an administrator, use the web interface (Objects >> Crypto Configuration >> SSH Client Profile) to configure an SSH Client Profile for the administrator user ID. Configure the "Persistent Idle Timeout" to 900 or less.'
  impact 0.5
  ref 'DPMS Target IBM DataPower XI52 NDM'
  tag check_id: 'C-65749r3_chk'
  tag severity: 'medium'
  tag gid: 'V-65121'
  tag rid: 'SV-79611r2_rule'
  tag stig_id: 'WSDP-NM-000081'
  tag gtitle: 'SRG-APP-000295-NDM-000279'
  tag fix_id: 'F-71061r3_fix'
  tag 'documentable'
  tag cci: ['CCI-002361']
  tag nist: ['AC-12']
end
